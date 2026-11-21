"""Baglam farkindalikli karar motoru.

FusionEngine saf bir durum makinesidir: olaylari alir, yapilacak aksiyonlarin
listesini dondurur. Aksiyonlari (surec oldurme, IP engelleme, oturum kilidi)
ai_fusion_worker uygular. Bu ayrim sayesinde karar mantigi ekran kilitlenmeden
birim testleriyle dogrulanabilir.

Protokoller (oncelik sirasiyla):
  1. Ag savunmasi   : NETWORK_SCAN -> saldirgan IP guvenlik duvarinda engellenir
  2. Donanim        : KEYBOARD_ANOMALY (BadUSB) -> oturum hemen kilitlenir
  3. Golge mudahale : SUSPICIOUS_PROCESS + DATA_EXFILTRATION, ya da Office
                      uygulamasindan kabuk acilmasi (USB/lokal ihlal yok)
                      -> sadece supheli surecler sessizce oldurulur
  4. Kill-chain     : risk >= esik -> surecler oldurulur + oturum kilitlenir
"""
import logging
import queue as queue_mod
import re
import time
from dataclasses import dataclass

from sentinel import events as ev
from sentinel.config import EVENT_WINDOW_SECONDS, KILL_CHAIN_THRESHOLD, LOCK_COOLDOWN_SECONDS, get_logger
from sentinel.engine import response
from sentinel.engine.risk import risk_skoru
from sentinel.sensors.process import OFFICE_ZINCIRI

log = get_logger("engine.fusion")

PID_REGEX = re.compile(r"\(PID:\s*(\d+),\s*CTIME:\s*([\d\.]+)\)")
IP_REGEX = re.compile(r"Kaynak IP:\s*([0-9a-fA-F\.:]+)")


@dataclass(frozen=True)
class Action:
    kind: str            # "block_ip" | "kill" | "lock" | "alert"
    target: tuple = ()   # block_ip: (ip,)  kill: (pid, ctime)  alert: (seviye, mesaj)


def _pid_aksiyonlari(olaylar, tipler):
    aksiyonlar = []
    for olay in olaylar:
        if olay["tip"] in tipler:
            m = PID_REGEX.search(olay["mesaj"])
            if m:
                aksiyon = Action("kill", (int(m.group(1)), float(m.group(2))))
                if aksiyon not in aksiyonlar:  # Ayni surec birden fazla kuralla yakalanmis olabilir
                    aksiyonlar.append(aksiyon)
    return aksiyonlar


class FusionEngine:
    def __init__(self, window=EVENT_WINDOW_SECONDS, threshold=KILL_CHAIN_THRESHOLD, cooldown=LOCK_COOLDOWN_SECONDS):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self.gecmis = []
        self.kilit_bitis = float("-inf")
        self.son_risk = 0.0

    def ingest(self, item, now):
        """Tek bir olayi pencereye ekler. Gecersiz olaylar False dondurur."""
        try:
            _katman, olay_tipi, _guven, mesaj = item
        except (TypeError, ValueError):
            return False
        # Kilit suresince olaylar degerlendirilmez (DB'ye yine de yazilir)
        if now >= self.kilit_bitis:
            self.gecmis.append({"zaman": now, "tip": olay_tipi, "mesaj": str(mesaj)})
        return True

    def evaluate(self, now):
        """Penceredeki olaylara gore yapilacak aksiyonlari dondurur."""
        self.gecmis = [o for o in self.gecmis if now - o["zaman"] <= self.window]
        tipler = {o["tip"] for o in self.gecmis}
        if not tipler:
            self.son_risk = 0.0
            return []

        # Korelasyon icin ag olaylari da skora dahil edilir
        risk = self.son_risk = risk_skoru(tipler)
        aksiyonlar = []

        # PROTOKOL 1: Ag savunmasi
        if ev.NETWORK_SCAN in tipler:
            aksiyonlar.append(Action("alert", ("WARNING", "AG TAARRUZU (port tarama) TESPIT EDILDI")))
            ipler = []
            for olay in self.gecmis:
                if olay["tip"] == ev.NETWORK_SCAN:
                    m = IP_REGEX.search(olay["mesaj"])
                    if m and m.group(1) not in ipler:
                        ipler.append(m.group(1))
            aksiyonlar += [Action("block_ip", (ip,)) for ip in ipler]
            # Ag olaylari islendi; diger olaylar (or. es zamanli lokal ihlal) korunur
            self.gecmis = [o for o in self.gecmis if o["tip"] != ev.NETWORK_SCAN]
            tipler.discard(ev.NETWORK_SCAN)
            if not tipler:
                return aksiyonlar

        # PROTOKOL 2: Donanimsal spoofing
        if ev.KEYBOARD_ANOMALY in tipler:
            aksiyonlar += [Action("alert", ("CRITICAL", "DONANIMSAL SPOOFING: insanustu klavye hizi")),
                           Action("lock")]
            self._sifirla(now, kilit=True)
            return aksiyonlar

        # PROTOKOL 3: Golge mudahale (sessiz savunma)
        office_zinciri = any(o["tip"] == ev.SUSPICIOUS_PROCESS and OFFICE_ZINCIRI in o["mesaj"] for o in self.gecmis)
        if (ev.USB_INSERTED not in tipler and ev.LOCAL_FILE_ACCESS not in tipler
                and ev.SUSPICIOUS_PROCESS in tipler and (ev.DATA_EXFILTRATION in tipler or office_zinciri)):
            neden = "Office makro zinciri" if office_zinciri else "Truva ati suphesi"
            aksiyonlar.append(Action("alert", ("WARNING", f"GOLGE MUDAHALE ({neden}) - risk {risk}")))
            aksiyonlar += _pid_aksiyonlari(self.gecmis, {ev.SUSPICIOUS_PROCESS, ev.DATA_EXFILTRATION})
            self._sifirla(now, kilit=False)
            return aksiyonlar

        # PROTOKOL 4: Kill-chain
        if risk >= self.threshold:
            aksiyonlar.append(Action("alert", ("CRITICAL", f"KILL-CHAIN: risk skoru {risk}")))
            aksiyonlar += _pid_aksiyonlari(
                self.gecmis, {ev.SUSPICIOUS_PROCESS, ev.LOCAL_FILE_ACCESS, ev.DATA_EXFILTRATION})
            aksiyonlar.append(Action("lock"))
            self._sifirla(now, kilit=True)
        return aksiyonlar

    def _sifirla(self, now, kilit):
        self.gecmis.clear()
        if kilit:
            self.kilit_bitis = now + self.cooldown


def uygula(aksiyon):
    if aksiyon.kind == "alert":
        seviye, mesaj = aksiyon.target
        log.log(getattr(logging, seviye), mesaj)
    elif aksiyon.kind == "block_ip":
        response.dinamik_ip_engelle(*aksiyon.target)
    elif aksiyon.kind == "kill":
        response.guvenli_surec_oldur(*aksiyon.target)
    elif aksiyon.kind == "lock":
        response.oturumu_kilitle()


def ai_fusion_worker(queue):
    log.info("Karar motoru baslatildi. Otonom savunma aktif.")
    motor = FusionEngine()

    while True:
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
            if not motor.ingest(item, su_an):
                log.warning("Gecersiz olay atlandi: %r", item)

        try:
            for aksiyon in motor.evaluate(su_an):
                uygula(aksiyon)
        except Exception:
            # Tek bir hatali olay tum savunma motorunu oldurmemeli
            log.exception("Karar motoru hatasi")
            motor.gecmis.clear()
