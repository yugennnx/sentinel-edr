from sentinel import events as ev
from sentinel.engine.fusion import Action, FusionEngine


def olay(tip, mesaj="", katman=ev.CYBER):
    return (katman, tip, 0.9, mesaj)


def turler(aksiyonlar):
    return [a.kind for a in aksiyonlar if a.kind != "alert"]


def test_ag_taramasi_ip_engeller_kilitlemez():
    m = FusionEngine()
    m.ingest(olay(ev.NETWORK_SCAN, "Honeypot -> Kaynak IP: 10.0.0.5", ev.NETWORK), 0)
    m.ingest(olay(ev.NETWORK_SCAN, "SYN -> Kaynak IP: 10.0.0.5", ev.NETWORK), 0)
    a = m.evaluate(0)
    assert turler(a) == ["block_ip"]
    assert Action("block_ip", ("10.0.0.5",)) in a


def test_tarama_esanli_lokal_ihlali_gizleyemez():
    m = FusionEngine()
    m.ingest(olay(ev.NETWORK_SCAN, "Kaynak IP: 10.0.0.5", ev.NETWORK), 0)
    m.ingest(olay(ev.LOCAL_FILE_ACCESS, "casus (PID: 42, CTIME: 1.5)"), 0)
    a = m.evaluate(0)
    assert "block_ip" in turler(a)
    assert Action("kill", (42, 1.5)) in a
    assert "lock" in turler(a)


def test_badusb_oturumu_kilitler():
    m = FusionEngine()
    m.ingest(olay(ev.KEYBOARD_ANOMALY, katman=ev.PHYSICAL), 0)
    assert turler(m.evaluate(0)) == ["lock"]


def test_golge_mudahale_kilitlemeden_oldurur():
    m = FusionEngine()
    m.ingest(olay(ev.SUSPICIOUS_PROCESS, "EDR: powershell.exe (PID: 7, CTIME: 2.0)"), 0)
    m.ingest(olay(ev.DATA_EXFILTRATION, "Veri Paketleme (PID: 7, CTIME: 2.0)"), 0)
    a = m.evaluate(0)
    assert "lock" not in turler(a)
    assert Action("kill", (7, 2.0)) in a


def test_tekil_supheli_surec_aksiyon_almaz():
    m = FusionEngine()
    m.ingest(olay(ev.SUSPICIOUS_PROCESS, "EDR: cmd.exe (PID: 9, CTIME: 3.0)"), 0)
    assert turler(m.evaluate(0)) == []


def test_kilit_sonrasi_bekleme_suresi():
    m = FusionEngine(cooldown=3)
    m.ingest(olay(ev.KEYBOARD_ANOMALY), 0)
    m.evaluate(0)
    m.ingest(olay(ev.KEYBOARD_ANOMALY), 1)   # bekleme suresinde: yok sayilir
    assert m.evaluate(1) == []
    m.ingest(olay(ev.KEYBOARD_ANOMALY), 5)   # sure doldu
    assert turler(m.evaluate(5)) == ["lock"]


def test_pencere_disindaki_olaylar_unutulur():
    m = FusionEngine(window=10)
    m.ingest(olay(ev.SUSPICIOUS_PROCESS, "(PID: 1, CTIME: 1.0)"), 0)
    m.ingest(olay(ev.DATA_EXFILTRATION), 20)
    assert turler(m.evaluate(20)) == []


def test_gecersiz_olay_reddedilir():
    m = FusionEngine()
    assert m.ingest("bozuk", 0) is False
    assert m.evaluate(0) == []


def test_office_makro_zinciri_golge_mudahale():
    m = FusionEngine()
    m.ingest(olay(ev.SUSPICIOUS_PROCESS,
                  "EDR: powershell.exe (PID: 5, CTIME: 1.0) | Neden: Zararli Parent-Child Baglantisi (winword.exe -> powershell.exe)"), 0)
    a = m.evaluate(0)
    assert turler(a) == ["kill"]


def test_ayni_surece_tek_kill():
    m = FusionEngine()
    m.ingest(olay(ev.SUSPICIOUS_PROCESS, "EDR: powershell.exe (PID: 7, CTIME: 2.0)"), 0)
    m.ingest(olay(ev.DATA_EXFILTRATION, "Veri Paketleme (PID: 7, CTIME: 2.0)"), 0)
    assert turler(m.evaluate(0)).count("kill") == 1
