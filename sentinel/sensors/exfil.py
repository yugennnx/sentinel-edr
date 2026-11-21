"""Veri sizdirma sensoru.

- T1560  Veri paketleme: arsivleme araclarinin korunan dizini hedeflemesi
- T1048  Yuksek ve surekli giden trafik (yukleme patlamasi)
"""
import time

import psutil

from sentinel import events as ev
from sentinel.config import (EXFIL_ALERT_COOLDOWN, EXFIL_SAMPLE_SECONDS, EXFIL_SUSTAINED_SAMPLES,
                             EXFIL_UPLOAD_BYTES_PER_SEC, get_logger)
from sentinel.sensors.process import korunan_dizini_hedefliyor

log = get_logger("sensors.exfil")

ARSIVLEYICILER = {"7z.exe", "7za.exe", "7zg.exe", "rar.exe", "winrar.exe", "tar.exe", "makecab.exe",
                  "zip.exe"}
POWERSHELL_ARSIV = ("compress-archive", "system.io.compression")


def paketleme_mi(name, cmdline):
    """Surec korunan dizini arsivliyorsa True."""
    name = (name or "").lower()
    if not korunan_dizini_hedefliyor(cmdline):
        return False
    if name in ARSIVLEYICILER:
        return True
    cmd = " ".join(cmdline or []).lower()
    return name in ("powershell.exe", "pwsh.exe") and any(k in cmd for k in POWERSHELL_ARSIV)


class UploadSpikeDetector:
    """Saniyedeki giden bayt, esigi art arda N ornek boyunca asarsa alarm verir."""

    def __init__(self, threshold=EXFIL_UPLOAD_BYTES_PER_SEC, sustained=EXFIL_SUSTAINED_SAMPLES,
                 cooldown=EXFIL_ALERT_COOLDOWN):
        self.threshold = threshold
        self.sustained = sustained
        self.cooldown = cooldown
        self.prev = None          # (zaman, bytes_sent)
        self.streak = 0
        self.last_alert = float("-inf")

    def feed(self, now, bytes_sent):
        """Yeni sayac degeri; alarm gerekiyorsa ortalama hizi (B/s), yoksa None dondurur."""
        if self.prev is None:
            self.prev = (now, bytes_sent)
            return None
        dt = now - self.prev[0]
        rate = (bytes_sent - self.prev[1]) / dt if dt > 0 else 0
        self.prev = (now, bytes_sent)

        self.streak = self.streak + 1 if rate > self.threshold else 0
        if self.streak >= self.sustained and now - self.last_alert > self.cooldown:
            self.last_alert = now
            self.streak = 0
            return rate
        return None


def exfil_worker(queue):
    log.info("Veri sizdirma sensoru aktif.")
    spike = UploadSpikeDetector()
    raporlananlar = set()
    son_ornek = float("-inf")

    while True:
        try:
            # 1) Yukleme patlamasi (sistem geneli) - her EXFIL_SAMPLE_SECONDS'ta bir ornek
            su_an = time.time()
            if su_an - son_ornek >= EXFIL_SAMPLE_SECONDS:
                son_ornek = su_an
                hiz = spike.feed(su_an, psutil.net_io_counters().bytes_sent)
                if hiz:
                    queue.put((ev.NETWORK, ev.DATA_EXFILTRATION, 0.6,
                               f"Yuksek giden trafik: {hiz / 1024 / 1024:.1f} MB/s (T1048)"))

            # 2) Korunan dizinin arsivlenmesi
            canli = set()
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    anahtar = (proc.info['pid'], proc.info.get('create_time'))
                    canli.add(anahtar)
                    if anahtar in raporlananlar:
                        continue
                    if paketleme_mi(proc.info.get('name'), proc.info.get('cmdline')):
                        queue.put((ev.CYBER, ev.DATA_EXFILTRATION, 0.9,
                                   f"Veri Paketleme (T1560): {proc.info['name']} korunan dizini arsivliyor "
                                   f"{ev.process_tag(*anahtar)}"))
                        raporlananlar.add(anahtar)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            raporlananlar &= canli
        except Exception:
            log.exception("Veri sizdirma sensoru hatasi")
        # Surec taramasi saniyede bir: kisa suren arsivleme islemleri de yakalanir
        time.sleep(1)
