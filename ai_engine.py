import ctypes
import ipaddress
import math
import queue as queue_mod
import re
import subprocess
import time

import psutil

from config import EVENT_WINDOW_SECONDS, KILL_CHAIN_THRESHOLD, LOCK_COOLDOWN_SECONDS, get_logger

log = get_logger("ai_engine")

PID_REGEX = re.compile(r"\(PID:\s*(\d+),\s*CTIME:\s*([\d\.]+)\)")
IP_REGEX = re.compile(r"Kaynak IP:\s*([0-9a-fA-F\.:]+)")

# Sentinel'in kendisini ve isletim sistemini asla oldurmemesi icin korunan surecler
KORUNAN_SURECLER = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                    "services.exe", "lsass.exe", "explorer.exe", "svchost.exe"}


def guvenli_surec_oldur(hedef_pid, hedef_ctime):
    """Sureci sadece PID VE baslangic zamani eslesirse oldurur (PID tekrar kullanimina karsi)."""
    try:
        p = psutil.Process(int(hedef_pid))
        if abs(p.create_time() - float(hedef_ctime)) > 0.01:
            log.info("PID %s artik farkli bir surece ait, dokunulmadi.", hedef_pid)
            return False
        if p.name().lower() in KORUNAN_SURECLER:
            log.warning("Korunan sistem sureci (%s) oldurulmedi.", p.name())
            return False
        p.kill()
        log.info("Zararli surec (PID: %s) imha edildi.", hedef_pid)
        return True
    except psutil.NoSuchProcess:
        return False
    except (psutil.AccessDenied, ValueError) as e:
        log.warning("Surec %s oldurulemedi: %s", hedef_pid, e)
        return False


# =========================================================
# OTONOM IPS: DİNAMİK GÜVENLİK DUVARI ENGELLEMESİ
# =========================================================
_engellenen_ipler = set()


def _yonetici_mi():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def ip_engellenebilir_mi(saldirgan_ip):
    """Sadece gecerli, loopback/yerel olmayan IP'ler engellenir. Gecersiz girdi komuta asla girmez."""
    try:
        ip = ipaddress.ip_address(saldirgan_ip)
    except ValueError:
        return False, "gecersiz IP"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return False, "loopback/ozel adres (sistem kararliligi)"
    return True, ""


def dinamik_ip_engelle(saldirgan_ip):
    uygun, neden = ip_engellenebilir_mi(saldirgan_ip)
    if not uygun:
        log.warning("%s engellenmedi: %s", saldirgan_ip, neden)
        return False
    if saldirgan_ip in _engellenen_ipler:
        return True  # Ayni IP icin tekrar tekrar kural olusturma
    if not _yonetici_mi():
        log.error("IPS: %s engellenemedi - Sentinel yonetici olarak calismiyor.", saldirgan_ip)
        return False

    kural_adi = f"Sentinel_Block_{saldirgan_ip}"
    # shell=True yerine arguman listesi: komut enjeksiyonu mumkun degil
    komut = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={kural_adi}",
             "dir=in", "action=block", f"remoteip={saldirgan_ip}"]
    try:
        sonuc = subprocess.run(komut, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("Firewall kurali eklenemedi: %s", e)
        return False

    if sonuc.returncode != 0:
        log.error("Firewall kurali eklenemedi (kod %s): %s", sonuc.returncode, (sonuc.stdout or sonuc.stderr).strip())
        return False
    _engellenen_ipler.add(saldirgan_ip)
    log.warning("IPS DEVREDE: %s guvenlik duvarinda KARA LISTEYE alindi.", saldirgan_ip)
    return True


def oturumu_kilitle():
    try:
        ctypes.windll.user32.LockWorkStation()
    except (AttributeError, OSError) as e:
        log.error("Oturum kilitlenemedi: %s", e)


# =========================================================
# RİSK SKORU (ağırlıklı toplam + sigmoid)
# =========================================================
def bulanik_mantik_hesapla(olaylar):
    taban_risk = 0.0

    if "KEYBOARD_ANOMALY" in olaylar: taban_risk += 40.0
    if "USB_INSERTED" in olaylar: taban_risk += 20.0
    if "SUSPICIOUS_PROCESS" in olaylar: taban_risk += 60.0
    if "NETWORK_SCAN" in olaylar: taban_risk += 75.0
    if "LOCAL_FILE_ACCESS" in olaylar: taban_risk += 85.0

    carpan = 1.0
    if "USB_INSERTED" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.4
    if "SUSPICIOUS_PROCESS" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.5
    if "LOCAL_FILE_ACCESS" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.6
    if "LOCAL_FILE_ACCESS" in olaylar and "NETWORK_SCAN" in olaylar: carpan += 0.6

    if len(olaylar) >= 3: carpan += 0.3

    ham_skor = taban_risk * carpan
    if ham_skor == 0: return 0.0
    nihai_risk = 100 / (1 + math.exp(-0.05 * (ham_skor - 50)))
    return round(nihai_risk, 2)


def _pidleri_oldur(olay_gecmisi, tipler):
    for olay in olay_gecmisi:
        if olay["tip"] in tipler:
            match = PID_REGEX.search(olay["mesaj"])
            if match:
                guvenli_surec_oldur(match.group(1), match.group(2))


def ai_fusion_worker(queue):
    log.info("Baglam farkindalikli karar motoru baslatildi. Otonom savunma aktif.")

    olay_gecmisi = []
    kilit_bitis = 0.0

    while True:
        # Kuyruktan olaylari al (bloklayarak, CPU'yu bosuna yakmadan)
        yeni = []
        try:
            yeni.append(queue.get(timeout=0.5))
            while True:
                yeni.append(queue.get_nowait())
        except queue_mod.Empty:
            pass
        su_an = time.time()

        for item in yeni:
            if item == "STOP":
                log.info("Karar motoru durduruldu.")
                return
            try:
                _katman, olay_tipi, _guven, mesaj = item
            except (TypeError, ValueError):
                log.warning("Gecersiz olay atlandi: %r", item)
                continue
            # Kilit suresince olaylar atilir (DB'ye yine de yazilir); kilit tekrar tetiklenmez
            if su_an < kilit_bitis:
                continue
            olay_gecmisi.append({"zaman": su_an, "tip": olay_tipi, "mesaj": mesaj})

        try:
            olay_gecmisi = [o for o in olay_gecmisi if su_an - o["zaman"] <= EVENT_WINDOW_SECONDS]
            benzersiz = {o["tip"] for o in olay_gecmisi}
            if not benzersiz:
                continue

            toplam_risk = bulanik_mantik_hesapla(benzersiz)

            # PROTOKOL 1: AĞ SAVUNMASI (DİNAMİK IPS)
            if "NETWORK_SCAN" in benzersiz:
                log.warning("AG TAARRUZU (port tarama) TESPIT EDILDI")
                for olay in olay_gecmisi:
                    if olay["tip"] == "NETWORK_SCAN":
                        match = IP_REGEX.search(olay["mesaj"])
                        if match:
                            dinamik_ip_engelle(match.group(1))
                # Diger olaylar (or. es zamanli lokal ihlal) korunur, sadece ag olaylari islenmis sayilir
                olay_gecmisi = [o for o in olay_gecmisi if o["tip"] != "NETWORK_SCAN"]
                benzersiz.discard("NETWORK_SCAN")
                if not benzersiz:
                    continue

            # PROTOKOL 2: Donanımsal spoofing (BadUSB)
            if "KEYBOARD_ANOMALY" in benzersiz:
                log.critical("DONANIMSAL SPOOFING: INSANUSTU KLAVYE HIZI - oturum kilitleniyor")
                oturumu_kilitle()
                olay_gecmisi.clear()
                kilit_bitis = su_an + LOCK_COOLDOWN_SECONDS
                continue

            # PROTOKOL 3: GÖLGE MÜDAHALE (Sessiz Savunma)
            if ("USB_INSERTED" not in benzersiz and "SUSPICIOUS_PROCESS" in benzersiz
                    and "DATA_EXFILTRATION" in benzersiz and "LOCAL_FILE_ACCESS" not in benzersiz):
                log.warning("UZAKTAN SALDIRI (Truva Ati suphesi) - risk %s, surec sessizce olduruluyor", toplam_risk)
                _pidleri_oldur(olay_gecmisi, {"SUSPICIOUS_PROCESS"})
                olay_gecmisi.clear()
                continue

            # PROTOKOL 4: KILL-CHAIN
            if toplam_risk >= KILL_CHAIN_THRESHOLD:
                log.critical("KILL-CHAIN: risk skoru %s - imha ve oturum kilidi", toplam_risk)
                _pidleri_oldur(olay_gecmisi, {"SUSPICIOUS_PROCESS", "LOCAL_FILE_ACCESS"})
                oturumu_kilitle()
                olay_gecmisi.clear()
                kilit_bitis = su_an + LOCK_COOLDOWN_SECONDS
        except Exception:
            # Tek bir hatali olay tum savunma motorunu oldurmemeli
            log.exception("Karar motoru hatasi")
            olay_gecmisi.clear()
