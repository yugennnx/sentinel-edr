"""Ag katmani: honeypot (tuzak port) ve SYN port tarama dedektoru."""
import socket
import time
from collections import defaultdict, deque

from sentinel import events as ev
from sentinel.config import (HONEYPOT_HOST, HONEYPOT_IP_COOLDOWN, HONEYPOT_PORT, SCAN_IP_COOLDOWN,
                             SCAN_PORT_THRESHOLD, SCAN_WINDOW_SECONDS, get_logger)

log = get_logger("sensors.network")


def scan_event(ip, aciklama):
    return (ev.NETWORK, ev.NETWORK_SCAN, 0.99, f"{aciklama} -> Kaynak IP: {ip}")


# ----------------------------------------------------------------------------
# Honeypot: hicbir mesru servisin kullanmadigi porta dokunan herkes suphelidir
# ----------------------------------------------------------------------------
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
        queue.put((ev.NETWORK, ev.ERROR, 1.0, f"Honeypot baslatilamadi: {e}"))
        return

    log.info("Honeypot aktif. Tuzak port: %s", HONEYPOT_PORT)
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
            ip, su_an = adres[0], time.time()
            if su_an - son_alarm.get(ip, float("-inf")) < HONEYPOT_IP_COOLDOWN:
                continue
            son_alarm[ip] = su_an
            queue.put(scan_event(ip, f"Honeypot Temasi (port {HONEYPOT_PORT})"))


# ----------------------------------------------------------------------------
# SYN tarama dedektoru (Nmap -sS gibi): kisa surede cok sayida farkli porta SYN
# ----------------------------------------------------------------------------
class PortScanDetector:
    """Kaynak IP basina, zaman penceresi icindeki farkli hedef portlari sayar."""

    def __init__(self, window=SCAN_WINDOW_SECONDS, threshold=SCAN_PORT_THRESHOLD, cooldown=SCAN_IP_COOLDOWN):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self._hits = defaultdict(deque)   # ip -> deque[(zaman, port)]
        self._last_alert = {}

    def feed(self, src_ip, dst_port, now):
        """Bir SYN paketi isler; tarama tespit edilirse port sayisini, yoksa None dondurur."""
        hits = self._hits[src_ip]
        hits.append((now, dst_port))
        while hits and now - hits[0][0] > self.window:
            hits.popleft()

        ports = {p for _, p in hits}
        if len(ports) >= self.threshold and now - self._last_alert.get(src_ip, float("-inf")) > self.cooldown:
            self._last_alert[src_ip] = now
            hits.clear()
            return len(ports)
        return None


def _yerel_ipler():
    import psutil
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET:
                ips.add(a.address)
    return ips


def scan_detector_worker(queue):
    """Npcap + scapy ile gelen SYN paketlerini dinler. Npcap yoksa sessizce devre disi kalir."""
    try:
        from scapy.all import IP, TCP, sniff
    except Exception as e:
        log.warning("SYN tarama dedektoru devre disi (scapy/Npcap yuklenemedi): %s", e)
        return

    detector = PortScanDetector()
    yerel = _yerel_ipler()

    def isle(paket):
        if IP not in paket or TCP not in paket:
            return
        ip, tcp = paket[IP], paket[TCP]
        if ip.dst not in yerel or ip.src in yerel:
            return
        sayi = detector.feed(ip.src, tcp.dport, time.time())
        if sayi:
            queue.put(scan_event(ip.src, f"SYN Port Taramasi ({sayi} farkli port / {int(detector.window)} sn)"))

    log.info("SYN tarama dedektoru aktif (esik: %d port / %d sn).", SCAN_PORT_THRESHOLD, SCAN_WINDOW_SECONDS)
    try:
        # Sadece SYN bayragi set, ACK set olmayan paketler (baglanti baslatma denemeleri)
        sniff(filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
              prn=isle, store=False)
    except Exception as e:
        log.error("SYN tarama dedektoru calisamadi (Npcap kurulu ve yonetici yetkisi var mi?): %s", e)
