"""Korelasyonlu risk skoru.

Pencere icindeki benzersiz olay tiplerinin agirliklari toplanir, birlikte gorulmesi
anlamli olan (korelasyonlu) olay ciftleri carpani artirir ve sonuc sigmoid ile
0-100 araligina sikistirilir. Tek basina zayif sinyaller esigi gecmez; birbirini
destekleyen sinyaller hizla kritik seviyeye cikar.
"""
import math

from sentinel import events as ev

AGIRLIKLAR = {
    ev.KEYBOARD_ANOMALY: 40.0,
    ev.USB_INSERTED: 20.0,
    ev.SUSPICIOUS_PROCESS: 60.0,
    ev.DATA_EXFILTRATION: 70.0,
    ev.NETWORK_SCAN: 75.0,
    ev.LOCAL_FILE_ACCESS: 85.0,
}

# (olay A, olay B) birlikte gorulurse carpana eklenecek deger
KORELASYONLAR = [
    ((ev.USB_INSERTED, ev.DATA_EXFILTRATION), 0.4),        # USB ile veri kacirma
    ((ev.SUSPICIOUS_PROCESS, ev.DATA_EXFILTRATION), 0.5),  # Truva ati veri cikariyor
    ((ev.LOCAL_FILE_ACCESS, ev.DATA_EXFILTRATION), 0.6),   # Hedefli veri hirsizligi
    ((ev.LOCAL_FILE_ACCESS, ev.NETWORK_SCAN), 0.6),        # Kesif + ihlal
]

SIGMOID_EGIM = 0.05
SIGMOID_MERKEZ = 50.0


def risk_skoru(olaylar):
    """Benzersiz olay tiplerinden 0-100 arasi risk skoru hesaplar."""
    olaylar = set(olaylar)
    taban = sum(AGIRLIKLAR.get(o, 0.0) for o in olaylar)
    if taban == 0:
        return 0.0

    carpan = 1.0 + sum(ek for (a, b), ek in KORELASYONLAR if a in olaylar and b in olaylar)
    if len(olaylar) >= 3:
        carpan += 0.3

    ham = taban * carpan
    return round(100 / (1 + math.exp(-SIGMOID_EGIM * (ham - SIGMOID_MERKEZ))), 2)


# Geriye donuk uyumluluk
bulanik_mantik_hesapla = risk_skoru
