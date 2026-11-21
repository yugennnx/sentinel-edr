from sentinel import events as ev
from sentinel.engine.risk import risk_skoru


def test_bos_olay_sifir():
    assert risk_skoru(set()) == 0.0
    assert risk_skoru({ev.USB_REMOVED}) == 0.0


def test_tekil_olaylar_esik_altinda_kalir():
    # Tek basina zayif sinyaller kill-chain esigini (80) gecmemeli
    for olay in (ev.USB_INSERTED, ev.KEYBOARD_ANOMALY, ev.SUSPICIOUS_PROCESS,
                 ev.DATA_EXFILTRATION, ev.NETWORK_SCAN):
        assert risk_skoru({olay}) < 80, olay


def test_lokal_ihlal_tek_basina_kritik():
    assert risk_skoru({ev.LOCAL_FILE_ACCESS}) >= 80


def test_korelasyon_skoru_artirir():
    tek = risk_skoru({ev.DATA_EXFILTRATION})
    usb_ile = risk_skoru({ev.DATA_EXFILTRATION, ev.USB_INSERTED})
    assert usb_ile > tek
    assert usb_ile >= 80  # USB ile veri kacirma kritik


def test_skor_sinirli():
    hepsi = {ev.KEYBOARD_ANOMALY, ev.USB_INSERTED, ev.SUSPICIOUS_PROCESS,
             ev.DATA_EXFILTRATION, ev.NETWORK_SCAN, ev.LOCAL_FILE_ACCESS}
    assert 0 <= risk_skoru(hepsi) <= 100
