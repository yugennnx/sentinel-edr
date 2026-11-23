"""Web panelinin veri yardimcilari (saf fonksiyonlar, Streamlit'e bagimli degil).

Panel bu fonksiyonlarla veritabani kayitlarindan anlik risk penceresini ve
okunabilir etiketleri uretir. Karar motorunun kendisine dokunulmaz: anlik risk,
motorla ayni risk fonksiyonu ve ayni pencere suresiyle, kayitlar uzerinden
yeniden hesaplanan bir gostergedir.
"""
from datetime import datetime

from sentinel import events as ev
from sentinel.config import EVENT_WINDOW_SECONDS
from sentinel.engine.risk import risk_skoru

ZAMAN_BICIMI = "%Y-%m-%d %H:%M:%S"

OLAY_ADI = {
    ev.KEYBOARD_ANOMALY: "BadUSB tuşlama",
    ev.USB_INSERTED: "USB takıldı",
    ev.USB_REMOVED: "USB çıkarıldı",
    ev.SUSPICIOUS_PROCESS: "Şüpheli süreç",
    ev.LOCAL_FILE_ACCESS: "Lokal ihlal",
    ev.DATA_EXFILTRATION: "Veri sızdırma",
    ev.NETWORK_SCAN: "Ağ taraması",
    ev.RESPONSE_ACTION: "Müdahale",
    ev.ERROR: "Sensör hatası",
}

KATMAN_ADI = {ev.PHYSICAL: "Fiziksel", ev.CYBER: "Siber", ev.NETWORK: "Ağ", ev.RESPONSE: "Müdahale"}


def olay_adi(olay_tipi):
    return OLAY_ADI.get(olay_tipi, str(olay_tipi))


def katman_adi(katman):
    return KATMAN_ADI.get(katman, str(katman))


def zaman(ts):
    try:
        return datetime.strptime(ts, ZAMAN_BICIMI)
    except (TypeError, ValueError):
        return None


def saniye_once(kayit, simdi):
    """Kaydin kac saniye once yazildigini dondurur; zaman okunamazsa None."""
    t = zaman(kayit.get("timestamp"))
    return None if t is None else (simdi - t).total_seconds()


def son_kayitlar(kayitlar, simdi, saniye):
    """Son `saniye` icindeki kayitlari (saniye_once, kayit) ciftleri olarak dondurur."""
    sonuc = []
    for k in kayitlar:
        once = saniye_once(k, simdi)
        if once is not None and -1 <= once <= saniye:
            sonuc.append((max(once, 0.0), k))
    return sonuc


def _tespit_mi(kayit):
    return kayit.get("layer") != ev.RESPONSE and kayit.get("event_type") != ev.ERROR


def pencere_riski(kayitlar, simdi, pencere=EVENT_WINDOW_SECONDS, rules=None):
    """Son `pencere` saniyedeki tespitlerden (mudahale kayitlari haric) risk skoru ve olay tiplerini dondurur."""
    tipler = {k["event_type"] for _, k in son_kayitlar(kayitlar, simdi, pencere) if _tespit_mi(k)}
    return risk_skoru(tipler, rules), sorted(tipler)


def risk_zirvesi(kayitlar, simdi, izleme, pencere=EVENT_WINDOW_SECONDS, rules=None):
    """Son `izleme` saniye icinde herhangi bir anda ulasilan en yuksek pencere riskini dondurur.

    Risk yalnizca olay anlarinda artabilecegi icin, her tespitin aninda biten pencere degerlendirilir.
    """
    tespitler = [(s, k) for s, k in son_kayitlar(kayitlar, simdi, izleme + pencere) if _tespit_mi(k)]
    zirve = 0.0
    for an, _ in tespitler:
        if an > izleme:
            continue
        tipler = {k["event_type"] for s, k in tespitler if an <= s <= an + pencere}
        zirve = max(zirve, risk_skoru(tipler, rules))
    return zirve
