import os
import socket
import time

import psutil

from config import (BASE_DIR, HONEYPOT_HOST, HONEYPOT_PORT, HONEYPOT_IP_COOLDOWN,
                    KEY_FAST_INTERVAL, KEY_FAST_COUNT, get_logger)

log = get_logger("sensors")


def _proc_connections(proc):
    """psutil 6+ 'net_connections', eski surumler 'connections' kullanir."""
    fn = getattr(proc, "net_connections", None) or proc.connections
    return fn(kind="inet")


# ==============================================================================
# 1. FİZİKSEL KATMAN SENSÖRÜ
# ==============================================================================
def physical_layer_worker(queue):
    # Windows'a ozel kutuphaneler sadece bu surecte yuklenir
    import pythoncom
    import wmi
    from pynput import keyboard

    pythoncom.CoInitialize()
    c = wmi.WMI()

    known_usb = {usb.DeviceID for usb in c.Win32_USBHub()}
    durum = {"son_zaman": time.time(), "son_tus": None, "hizli": 0, "son_alarm": 0.0}

    def on_press(key):
        su_an = time.time()
        fark = su_an - durum["son_zaman"]
        durum["son_zaman"] = su_an

        # Basili tutulan tusun otomatik tekrari (ayni tus) insan davranisidir, BadUSB degil.
        ayni_tus = key == durum["son_tus"]
        durum["son_tus"] = key

        if fark < KEY_FAST_INTERVAL and not ayni_tus:
            durum["hizli"] += 1
        else:
            durum["hizli"] = 0

        if durum["hizli"] > KEY_FAST_COUNT and (su_an - durum["son_alarm"]) > 2.0:
            queue.put(("PHYSICAL", "KEYBOARD_ANOMALY", 0.9, "BadUSB Suphesi: Kesintisiz hizli tuslama"))
            durum["son_alarm"] = su_an
            durum["hizli"] = 0

    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    try:
        while True:
            time.sleep(5)
            current_usb = {usb.DeviceID for usb in c.Win32_USBHub()}

            for dev in current_usb - known_usb:
                queue.put(("PHYSICAL", "USB_INSERTED", 0.6, f"Yeni Cihaz: {dev}"))
            for dev in known_usb - current_usb:
                queue.put(("PHYSICAL", "USB_REMOVED", 0.1, f"Cihaz Cikarildi: {dev}"))
            known_usb = current_usb

    except Exception as e:
        log.exception("Fiziksel sensor hatasi")
        queue.put(("PHYSICAL", "ERROR", 1.0, str(e)))
    finally:
        listener.stop()
        pythoncom.CoUninitialize()


# ==============================================================================
# 2. SİBER KATMAN SENSÖRÜ (EDR)
# ==============================================================================
TEHLIKELI_EBEVEYNLER = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'acrobat.exe', 'outlook.exe'}
HEDEF_KABUKLAR = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}
ZARARLI_PARAMETRELER = ['-enc', 'bypass', 'hidden', 'downloadstring', 'invoke-webrequest',
                        'bitsadmin', 'certutil', 'iex', 'frombase64string']
GUVENLI_PORTLAR = {80, 443}

DASHBOARD_YOLU = os.path.normcase(os.path.join(BASE_DIR, "dashboard.py"))


def _guvenli_dashboard_sureci(cmdline):
    """Yalnizca BU projedeki dashboard'u baslatan 'streamlit run' komutunu beyaz listeye alir.

    Eskiden komut satirinda 'streamlit' kelimesi gecmesi yetiyordu; saldirgan
    komutuna bu kelimeyi ekleyerek EDR'yi tamamen atlatabiliyordu.
    """
    tokens = [t.strip('"').lower() for t in cmdline]
    if "streamlit" not in " ".join(tokens) or "run" not in tokens:
        return False
    if any(p in " ".join(tokens) for p in ZARARLI_PARAMETRELER):
        return False
    return any(os.path.normcase(os.path.abspath(t)) == DASHBOARD_YOLU for t in cmdline)


def analiz_et(name, cmdline, parent_name, baglantilar):
    """Tek bir kabuk sureci icin tespit nedenlerini dondurur (test edilebilir saf fonksiyon)."""
    nedenler = []
    if parent_name in TEHLIKELI_EBEVEYNLER:
        nedenler.append(f"Zararli Parent-Child Baglantisi ({parent_name} -> {name})")

    cmd_str = " ".join(cmdline).lower() if cmdline else ""
    for param in ZARARLI_PARAMETRELER:
        if param in cmd_str.split() or (len(param) > 3 and param in cmd_str):
            nedenler.append(f"Kritik Payload Parametresi Yakalandi ({param})")
            break

    for ip, port in baglantilar:
        if port not in GUVENLI_PORTLAR and not ip.startswith("127.") and ip != "::1":
            nedenler.append(f"Ters Baglanti Tespiti -> Hedef: {ip}:{port}")
            break
    return nedenler


def cyber_layer_worker(queue):
    time.sleep(3)
    log.info("Siber Katman (EDR Modu) aktif. Davranissal analiz basladi...")

    # PID'ler Windows'ta tekrar kullanilir: (pid, create_time) ciftiyle takip edilir
    raporlananlar = set()

    while True:
        canli = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time']):
                try:
                    pid = proc.info['pid']
                    name = str(proc.info['name']).lower()
                    anahtar = (pid, proc.info.get('create_time'))
                    canli.add(anahtar)

                    if name not in HEDEF_KABUKLAR or anahtar in raporlananlar:
                        continue

                    cmdline = proc.info.get('cmdline') or []
                    if _guvenli_dashboard_sureci(cmdline):
                        continue

                    parent_name = ""
                    ppid = proc.info.get('ppid')
                    if ppid:
                        try:
                            parent_name = psutil.Process(ppid).name().lower()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    baglantilar = []
                    try:
                        for conn in _proc_connections(proc):
                            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                                baglantilar.append((conn.raddr.ip, conn.raddr.port))
                    except psutil.AccessDenied:
                        pass

                    nedenler = analiz_et(name, cmdline, parent_name, baglantilar)
                    if nedenler:
                        ctime = proc.info.get('create_time', 0.0)
                        detay = f"EDR: {name} (PID: {pid}, CTIME: {ctime}) | Neden: {' | '.join(nedenler)}"
                        queue.put(("CYBER", "SUSPICIOUS_PROCESS", 0.99, detay))
                        raporlananlar.add(anahtar)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            log.exception("Siber sensor tarama hatasi")

        # Olen sureclerin kayitlari silinir: kume sonsuza kadar buyumez
        raporlananlar &= canli
        time.sleep(2)


# ==============================================================================
# 3. AĞ KATMANI SENSÖRÜ (Bal Küpü / Honeypot)
# ==============================================================================
def network_layer_worker(queue):
    try:
        tuzak = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows: baska bir programin ayni portu ele gecirmesini (port hijack) engeller
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            tuzak.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        tuzak.bind((HONEYPOT_HOST, HONEYPOT_PORT))
        tuzak.listen(16)
    except OSError as e:
        log.error("Honeypot portu (%s) acilamadi: %s", HONEYPOT_PORT, e)
        queue.put(("NETWORK", "ERROR", 1.0, f"Honeypot baslatilamadi: {e}"))
        return

    log.info("Ag katmani sensoru (honeypot) aktif. Tuzak port: %s", HONEYPOT_PORT)
    son_alarm = {}  # ip -> zaman; ayni IP'den gelen seri baglantilar tek alarm uretir

    with tuzak:
        while True:
            try:
                baglanti, adres = tuzak.accept()
            except OSError as e:
                log.warning("Honeypot accept hatasi: %s", e)
                time.sleep(1)
                continue

            baglanti.close()
            saldirgan_ip = adres[0]
            su_an = time.time()
            if su_an - son_alarm.get(saldirgan_ip, 0.0) < HONEYPOT_IP_COOLDOWN:
                continue
            son_alarm[saldirgan_ip] = su_an
            queue.put(("NETWORK", "NETWORK_SCAN", 0.99, f"Ag Taramasi Tespiti -> Kaynak IP: {saldirgan_ip}"))


# ==============================================================================
# 4. LOKAL DAVRANIŞ ANALİZİ (SUNUM MODU)
# ==============================================================================
LOKAL_IMZALAR = {
    "lokal_saldiri": "Lokal Ihlal (Casus Yazilim): Sizma Tespit Edildi (PID: {pid}, CTIME: {ctime}) -> Sentinel Hedeflendi",
    "veri_paketleme": "Lokal Ihlal (Veri Paketleme/Dripping): Arsivleme Tespit Edildi (PID: {pid}, CTIME: {ctime}) -> Sentinel Kopyalaniyor",
}


def local_behavior_worker(queue):
    log.info("Lokal Davranis Analizcisi (LBA) aktif. Sunum modu devrede...")
    raporlananlar = set()

    while True:
        canli = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    if (proc.info.get('name') or '').lower() != "cmd.exe":
                        continue
                    cmdline = proc.info.get('cmdline')
                    if not cmdline:
                        continue

                    anahtar = (proc.info['pid'], proc.info.get('create_time'))
                    canli.add(anahtar)
                    if anahtar in raporlananlar:
                        continue  # Ayni sureci her saniye tekrar raporlama

                    cmd_str = " ".join(cmdline).lower()
                    for imza, sablon in LOKAL_IMZALAR.items():
                        if imza in cmd_str:
                            detay = sablon.format(pid=anahtar[0], ctime=anahtar[1] or 0.0)
                            queue.put(("CYBER", "LOCAL_FILE_ACCESS", 0.99, detay))
                            raporlananlar.add(anahtar)
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            log.exception("Lokal davranis sensoru hatasi")

        raporlananlar &= canli
        time.sleep(1)
