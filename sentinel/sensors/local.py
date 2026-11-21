"""Lokal davranis analizi (sunum modu).

simulator/ klasorundeki demo .bat senaryolarini imzalarindan tanir. Gercek
saldirilar icin maskeleme (process.py) ve veri paketleme (exfil.py) kurallari
kullanilir; bu sensor sunumda tekrarlanabilir bir tetikleyici saglar.
"""
import time

import psutil

from sentinel import events as ev
from sentinel.config import get_logger

log = get_logger("sensors.local")

LOKAL_IMZALAR = {
    "lokal_saldiri": "Lokal Ihlal (Casus Yazilim): Sizma Tespit Edildi {tag} -> Sentinel Hedeflendi",
    "veri_paketleme": "Lokal Ihlal (Veri Paketleme/Dripping): Arsivleme Tespit Edildi {tag} -> Sentinel Kopyalaniyor",
}


def imza_bul(cmdline):
    cmd_str = " ".join(cmdline or []).lower()
    for imza, sablon in LOKAL_IMZALAR.items():
        if imza in cmd_str:
            return sablon
    return None


def local_behavior_worker(queue):
    log.info("Lokal davranis analizcisi (sunum modu) aktif.")
    raporlananlar = set()

    while True:
        canli = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    if (proc.info.get('name') or '').lower() != "cmd.exe":
                        continue
                    anahtar = (proc.info['pid'], proc.info.get('create_time'))
                    canli.add(anahtar)
                    if anahtar in raporlananlar:
                        continue  # Ayni sureci her saniye tekrar raporlama
                    sablon = imza_bul(proc.info.get('cmdline'))
                    if sablon:
                        queue.put((ev.CYBER, ev.LOCAL_FILE_ACCESS, 0.99, sablon.format(tag=ev.process_tag(*anahtar))))
                        raporlananlar.add(anahtar)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            log.exception("Lokal davranis sensoru hatasi")

        raporlananlar &= canli
        time.sleep(1)
