"""Siber katman (EDR): surec davranis analizi.

Kurallar rules/sentinel_rules.yaml dosyasindan okunur:
- process_rules : parent-child, komut satiri ve ag baglantisi kurallari
- masquerade    : sistem aracinin baska bir adla kopyalanip calistirilmasi (T1036.003)
"""
import os
import time

import psutil

from sentinel import events as ev
from sentinel.config import BASE_DIR, PROTECTED_DIR, get_logger
from sentinel.rules import get_rules

log = get_logger("sensors.process")

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
    # Komut satiri bir tespit kuralina takiliyorsa beyaz liste gecersiz
    if analiz_et("powershell.exe", cmdline, "", []):
        return False
    return any(os.path.normcase(os.path.abspath(t.strip('"'))) == DASHBOARD_YOLU for t in cmdline)


def izlenen_surecler(rules=None):
    """Herhangi bir surec kuralinin hedefledigi surec adlari."""
    rules = rules or get_rules()
    return frozenset().union(*(r.process_names for r in rules.process_rules))


def analiz_et(name, cmdline, parent_name, baglantilar, rules=None):
    """Bir surec icin eslesen kurallarin aciklamalarini dondurur (saf fonksiyon, test edilebilir)."""
    rules = rules or get_rules()
    sonuc = []
    for kural in rules.process_rules:
        aciklama = kural.match(name, cmdline, parent_name, baglantilar)
        if aciklama:
            sonuc.append(aciklama)
    return sonuc


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


def maskeleme_kontrol(calisan_ad, orijinal_ad, rules=None):
    """Calisan ad, sistem aracinin gercek adindan farkliysa maskelenen aracin adini dondurur."""
    if not orijinal_ad:
        return None
    izlenen = (rules or get_rules()).masquerade["watched_binaries"]
    gercek = orijinal_ad.lower().removesuffix(".mui")
    if gercek in izlenen and calisan_ad.lower() != gercek:
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
    rules = get_rules()
    hedef_surecler = izlenen_surecler(rules)
    masq = rules.masquerade
    log.info("Siber katman (EDR) aktif: %d surec kurali + maskeleme.", len(rules.process_rules))

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
                    maskelenen = maskeleme_kontrol(name, pe_orijinal_ad(exe), rules) if exe else None
                    if maskelenen:
                        tag = ev.process_tag(pid, ctime)
                        kural = f"[{masq.get('id', 'MASQ')}] {masq.get('name', 'Maskeleme')} ({maskelenen} kopyasi)"
                        if korunan_dizini_hedefliyor(cmdline):
                            queue.put((ev.CYBER, ev.LOCAL_FILE_ACCESS, 0.99,
                                       f"EDR: {name} {tag} | Neden: {kural} korunan dizini hedefliyor"))
                        else:
                            queue.put((ev.CYBER, ev.SUSPICIOUS_PROCESS, 0.95, f"EDR: {name} {tag} | Neden: {kural}"))
                        raporlananlar.add(anahtar)
                        continue

                    # 2) Kabuk davranis kurallari
                    if name not in hedef_surecler or guvenli_dashboard_sureci(cmdline):
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

                    nedenler = analiz_et(name, cmdline, parent_name, baglantilar, rules)
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
