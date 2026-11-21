"""Otonom mudahale aksiyonlari: surec imhasi, IP engelleme, oturum kilidi."""
import ctypes
import ipaddress
import subprocess

import psutil

from sentinel.config import get_logger

log = get_logger("engine.response")

# Sentinel'in isletim sistemini asla oldurmemesi icin korunan surecler
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
        log.warning("Zararli surec imha edildi: %s (PID %s)", p.name(), hedef_pid)
        return True
    except psutil.NoSuchProcess:
        return False
    except (psutil.AccessDenied, ValueError) as e:
        log.warning("Surec %s oldurulemedi: %s", hedef_pid, e)
        return False


_engellenen_ipler = set()


def yonetici_mi():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def ip_engellenebilir_mi(saldirgan_ip):
    """Sadece gecerli, loopback/ozel amacli olmayan IP'ler engellenir. Gecersiz girdi komuta asla girmez."""
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
    if not yonetici_mi():
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
        log.warning("Oturum kilitlendi.")
    except (AttributeError, OSError) as e:
        log.error("Oturum kilitlenemedi: %s", e)
