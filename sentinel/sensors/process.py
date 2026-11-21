"""Siber katman (EDR): surec davranis analizi.

Kurallar (MITRE ATT&CK):
- T1566/T1204  Office/PDF uygulamasindan kabuk acilmasi (parent-child)
- T1059/T1027  Kabukta supheli parametre (-enc, bypass, hidden, iex ...)
- T1071        Kabugun 80/443 disi bir porta disari baglanmasi (ters kabuk)
- T1036.003    Maskeleme: cmd.exe / powershell.exe gibi bir sistem aracinin
               baska bir adla kopyalanip calistirilmasi
"""
import os
import time

import psutil

from sentinel import events as ev
from sentinel.config import BASE_DIR, PROTECTED_DIR, get_logger

log = get_logger("sensors.process")

TEHLIKELI_EBEVEYNLER = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'acrobat.exe', 'outlook.exe'}
HEDEF_KABUKLAR = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}
ZARARLI_PARAMETRELER = ['-enc', 'bypass', 'hidden', 'downloadstring', 'invoke-webrequest',
                        'bitsadmin', 'certutil', 'iex', 'frombase64string']
GUVENLI_PORTLAR = {80, 443}
OFFICE_ZINCIRI = "Zararli Parent-Child Baglantisi"  # Karar motoru bu isareti arar

# Maskelemede izlenen sistem araclari (PE dosyasindaki OriginalFilename -> gercek ad)
LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
           "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}

DASHBOARD_YOLU = os.path.normcase(os.path.join(BASE_DIR, "sentinel", "ui", "dashboard.py"))


def _proc_connections(proc):
    """psutil 6+ 'net_connections', eski surumler 'connections' kullanir."""
    fn = getattr(proc, "net_connections", None) or proc.connections
    return fn(kind="inet")


def guvenli_dashboard_sureci(cmdline):
    """Yalnizca BU projedeki dashboard'u baslatan 'streamlit run' komutunu beyaz listeye alir."""
    tokens = [t.strip('"').lower() for t in cmdline]
    birlesik = " ".join(tokens)
    if "streamlit" not in birlesik or "run" not in tokens:
        return False
    if any(p in birlesik for p in ZARARLI_PARAMETRELER):
        return False
    return any(os.path.normcase(os.path.abspath(t.strip('"'))) == DASHBOARD_YOLU for t in cmdline)


def analiz_et(name, cmdline, parent_name, baglantilar):
    """Tek bir kabuk sureci icin tespit nedenlerini dondurur (saf fonksiyon, test edilebilir)."""
    nedenler = []
    if parent_name in TEHLIKELI_EBEVEYNLER:
        nedenler.append(f"{OFFICE_ZINCIRI} ({parent_name} -> {name})")

    cmd_str = " ".join(cmdline).lower() if cmdline else ""
    for param in ZARARLI_PARAMETRELER:
        # Kisa parametreler (iex) sadece tam kelime olarak aranir: "iexplore" yanlis alarm vermesin
        if param in cmd_str.split() or (len(param) > 3 and param in cmd_str):
            nedenler.append(f"Kritik Payload Parametresi Yakalandi ({param})")
            break

    for ip, port in baglantilar:
        if port not in GUVENLI_PORTLAR and not ip.startswith("127.") and ip != "::1":
            nedenler.append(f"Ters Baglanti Tespiti -> Hedef: {ip}:{port}")
            break
    return nedenler


# ----------------------------------------------------------------------------
# Maskeleme (T1036.003)
# ----------------------------------------------------------------------------
_orijinal_ad_cache = {}


def pe_orijinal_ad(exe_path):
    """Calistirilabilir dosyanin surum bilgisindeki OriginalFilename degerini dondurur."""
    if exe_path in _orijinal_ad_cache:
        return _orijinal_ad_cache[exe_path]
    ad = None
    try:
        import win32api
        lang, cp = win32api.GetFileVersionInfo(exe_path, "\\VarFileInfo\\Translation")[0]
        ad = win32api.GetFileVersionInfo(exe_path, f"\\StringFileInfo\\{lang:04X}{cp:04X}\\OriginalFilename")
    except Exception:
        ad = None
    _orijinal_ad_cache[exe_path] = ad
    return ad


def maskeleme_kontrol(calisan_ad, orijinal_ad):
    """Calisan ad, sistem aracinin gercek adindan farkliysa maskelenen aracin adini dondurur."""
    if not orijinal_ad:
        return None
    gercek = orijinal_ad.lower().removesuffix(".mui")
    if gercek in LOLBINS and calisan_ad.lower() != gercek:
        return gercek
    return None


def korunan_dizini_hedefliyor(cmdline, korunan=PROTECTED_DIR):
    """Argumanlardan biri korunan dizini iceriyorsa True.

    cmdline[0] (programin kendi yolu) sayilmaz: programin proje klasorunde
    bulunmasi, o klasoru hedef aldigi anlamina gelmez.
    """
    hedef = os.path.normcase(korunan)
    return any(hedef in os.path.normcase(arg) for arg in (cmdline or [])[1:])


def cyber_layer_worker(queue):
    time.sleep(3)
    log.info("Siber katman (EDR) aktif. Davranissal analiz basladi...")

    # PID'ler Windows'ta tekrar kullanilir: (pid, create_time) ciftiyle takip edilir
    raporlananlar = set()

    while True:
        canli = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time', 'exe']):
                try:
                    pid = proc.info['pid']
                    name = str(proc.info['name']).lower()
                    ctime = proc.info.get('create_time')
                    anahtar = (pid, ctime)
                    canli.add(anahtar)
                    if anahtar in raporlananlar:
                        continue

                    cmdline = proc.info.get('cmdline') or []
                    exe = proc.info.get('exe')

                    # 1) Maskelenmis sistem araci
                    maskelenen = maskeleme_kontrol(name, pe_orijinal_ad(exe)) if exe else None
                    if maskelenen:
                        tag = ev.process_tag(pid, ctime)
                        if korunan_dizini_hedefliyor(cmdline):
                            queue.put((ev.CYBER, ev.LOCAL_FILE_ACCESS, 0.99,
                                       f"Maskelenmis {maskelenen} korunan dizini hedefliyor: {name} {tag}"))
                        else:
                            queue.put((ev.CYBER, ev.SUSPICIOUS_PROCESS, 0.95,
                                       f"EDR: {name} {tag} | Neden: Maskeleme ({maskelenen} kopyasi, T1036)"))
                        raporlananlar.add(anahtar)
                        continue

                    # 2) Kabuk davranis kurallari
                    if name not in HEDEF_KABUKLAR or guvenli_dashboard_sureci(cmdline):
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
                        detay = f"EDR: {name} {ev.process_tag(pid, ctime)} | Neden: {' | '.join(nedenler)}"
                        queue.put((ev.CYBER, ev.SUSPICIOUS_PROCESS, 0.99, detay))
                        raporlananlar.add(anahtar)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            log.exception("Siber sensor tarama hatasi")

        # Olen sureclerin kayitlari silinir: kume sonsuza kadar buyumez
        raporlananlar &= canli
        time.sleep(2)
