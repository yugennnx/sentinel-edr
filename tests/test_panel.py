from datetime import datetime, timedelta

from sentinel import events as ev
from sentinel.engine.risk import risk_skoru
from sentinel.ui import panel_veri as pv

SIMDI = datetime(2026, 11, 23, 12, 0, 0)


def kayit(saniye_once, katman, tip):
    ts = (SIMDI - timedelta(seconds=saniye_once)).strftime(pv.ZAMAN_BICIMI)
    return {"timestamp": ts, "layer": katman, "event_type": tip, "confidence": 1.0, "message": ""}


def test_bos_pencere_sifir_risk():
    assert pv.pencere_riski([], SIMDI) == (0.0, [])


def test_pencere_motorla_ayni_skoru_verir():
    kayitlar = [kayit(2, ev.PHYSICAL, ev.USB_INSERTED), kayit(5, ev.CYBER, ev.DATA_EXFILTRATION)]
    risk, tipler = pv.pencere_riski(kayitlar, SIMDI)
    assert tipler == sorted([ev.USB_INSERTED, ev.DATA_EXFILTRATION])
    assert risk == risk_skoru({ev.USB_INSERTED, ev.DATA_EXFILTRATION})
    assert risk >= 80


def test_pencere_disi_ve_mudahale_kayitlari_sayilmaz():
    kayitlar = [kayit(30, ev.CYBER, ev.DATA_EXFILTRATION),             # pencere disinda
                kayit(1, ev.RESPONSE, ev.RESPONSE_ACTION),             # karar kaydi
                kayit(1, ev.NETWORK, ev.ERROR),                        # sensor hatasi
                {"timestamp": "bozuk", "layer": ev.CYBER, "event_type": ev.NETWORK_SCAN}]
    assert pv.pencere_riski(kayitlar, SIMDI) == (0.0, [])


def test_zirve_gecmis_saldiriyi_hatirlar():
    # USB ve veri sizdirma 6 sn arayla, 30 sn once oldu: anlik risk 0 ama zirve esigi asmis olmali
    kayitlar = [kayit(36, ev.PHYSICAL, ev.USB_INSERTED), kayit(30, ev.CYBER, ev.DATA_EXFILTRATION)]
    assert pv.pencere_riski(kayitlar, SIMDI)[0] == 0.0
    assert pv.risk_zirvesi(kayitlar, SIMDI, 60) == risk_skoru({ev.USB_INSERTED, ev.DATA_EXFILTRATION})


def test_zirve_uzak_olaylari_birlestirmez():
    # 20 sn arayla gelen iki olay ayni pencereye girmez: zirve tekil olayin skoru
    kayitlar = [kayit(40, ev.PHYSICAL, ev.USB_INSERTED), kayit(20, ev.CYBER, ev.DATA_EXFILTRATION)]
    assert pv.risk_zirvesi(kayitlar, SIMDI, 60) == risk_skoru({ev.DATA_EXFILTRATION})


def test_son_kayitlar_saniyeyi_dondurur():
    sonuc = pv.son_kayitlar([kayit(12, ev.CYBER, ev.SUSPICIOUS_PROCESS), kayit(90, ev.CYBER, ev.SUSPICIOUS_PROCESS)],
                            SIMDI, 60)
    assert [round(s) for s, _ in sonuc] == [12]


def test_etiketler_turkce_ve_bilinmeyende_ham_ad():
    assert pv.olay_adi(ev.NETWORK_SCAN) == "Ağ taraması"
    assert pv.katman_adi(ev.RESPONSE) == "Müdahale"
    assert pv.olay_adi("YENI_TIP") == "YENI_TIP"
