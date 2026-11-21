import os

from sentinel.config import PROTECTED_DIR
from sentinel.sensors import process
from sentinel.sensors.exfil import UploadSpikeDetector, paketleme_mi
from sentinel.sensors.local import imza_bul
from sentinel.sensors.network import PortScanDetector
from sentinel.sensors.physical import KeystrokeAnalyzer


# --- EDR kurallari ----------------------------------------------------------
def test_gizli_powershell_yakalanir():
    n = process.analiz_et("powershell.exe", ["powershell", "-WindowStyle", "Hidden"], "explorer.exe", [])
    assert any("hidden" in x for x in n)


def test_office_ebeveyn_ve_ters_baglanti():
    n = process.analiz_et("cmd.exe", ["cmd", "/c", "dir"], "winword.exe", [("8.8.8.8", 4444)])
    assert len(n) == 2


def test_temiz_kabuk_alarm_vermez():
    assert process.analiz_et("cmd.exe", ["cmd", "/c", "dir"], "explorer.exe", [("1.1.1.1", 443)]) == []


def test_kisa_parametre_kelime_icinde_yanlis_alarm_vermez():
    assert process.analiz_et("cmd.exe", ["cmd", "/c", "start", "iexplore.exe"], "explorer.exe", []) == []


def test_streamlit_kelimesi_beyaz_listeyi_atlatamaz():
    assert not process.guvenli_dashboard_sureci(["powershell", "-enc", "AAA", "#streamlit"])
    assert process.guvenli_dashboard_sureci(["cmd", "/c", "streamlit", "run", process.DASHBOARD_YOLU])


# --- Maskeleme --------------------------------------------------------------
def test_maskeleme_tespiti():
    assert process.maskeleme_kontrol("siber_casus.exe", "Cmd.Exe") == "cmd.exe"
    assert process.maskeleme_kontrol("winword.exe", "Cmd.Exe") == "cmd.exe"
    assert process.maskeleme_kontrol("golge.exe", "PowerShell.EXE.MUI") == "powershell.exe"


def test_gercek_sistem_araci_maskeleme_degil():
    assert process.maskeleme_kontrol("cmd.exe", "Cmd.Exe.MUI") is None
    assert process.maskeleme_kontrol("chrome.exe", "chrome.exe") is None
    assert process.maskeleme_kontrol("x.exe", None) is None


def test_korunan_dizin_hedefleme():
    assert process.korunan_dizini_hedefliyor(["x", f'echo {os.path.join(PROTECTED_DIR, "a.txt")}'])
    assert not process.korunan_dizini_hedefliyor(["cmd", "/c", "dir", "C:\\Windows"])


# --- Veri sizdirma ----------------------------------------------------------
def test_korunan_dizini_arsivleme():
    hedef = os.path.join(PROTECTED_DIR, "sentinel")
    assert paketleme_mi("7z.exe", ["7z", "a", "out.7z", hedef])
    assert paketleme_mi("powershell.exe", ["powershell", f"Compress-Archive -Path '{hedef}' -DestinationPath x.zip"])
    assert not paketleme_mi("7z.exe", ["7z", "a", "out.7z", "C:\\Baska"])
    assert not paketleme_mi("notepad.exe", ["notepad", hedef])


def test_yukleme_patlamasi_surekli_olmali():
    d = UploadSpikeDetector(threshold=1000, sustained=3, cooldown=60)
    assert d.feed(0, 0) is None
    assert d.feed(1, 5000) is None       # 1. yuksek ornek
    assert d.feed(2, 10000) is None      # 2.
    assert d.feed(3, 15000) == 5000      # 3. -> alarm
    assert d.feed(4, 20000) is None      # bekleme suresi


def test_kisa_yukleme_alarm_vermez():
    d = UploadSpikeDetector(threshold=1000, sustained=3)
    d.feed(0, 0)
    d.feed(1, 5000)
    d.feed(2, 5100)                      # dusus seriyi sifirlar
    assert d.feed(3, 10000) is None


# --- Ag ---------------------------------------------------------------------
def test_syn_tarama_tespiti():
    d = PortScanDetector(window=10, threshold=15, cooldown=30)
    sonuc = [d.feed("10.0.0.9", port, 0.1 * i) for i, port in enumerate(range(1, 16))]
    assert sonuc[-1] == 15 and all(s is None for s in sonuc[:-1])


def test_ayni_porta_tekrar_baglanti_tarama_degil():
    d = PortScanDetector(threshold=15)
    assert all(d.feed("10.0.0.9", 443, i * 0.1) is None for i in range(100))


def test_yavas_tarama_pencereden_duser():
    d = PortScanDetector(window=10, threshold=15)
    assert all(d.feed("10.0.0.9", p, p * 5) is None for p in range(1, 30))


# --- Fiziksel ---------------------------------------------------------------
def test_badusb_hizli_farkli_tuslar():
    k = KeystrokeAnalyzer(fast_interval=0.02, fast_count=5)
    sonuc = [k.feed(f"k{i}", i * 0.005) for i in range(8)]
    assert any(sonuc)


def test_basili_tutulan_tus_alarm_vermez():
    k = KeystrokeAnalyzer(fast_interval=0.02, fast_count=5)
    assert not any(k.feed("a", i * 0.005) for i in range(50))


def test_insan_hizinda_yazim_alarm_vermez():
    k = KeystrokeAnalyzer(fast_interval=0.02, fast_count=5)
    assert not any(k.feed(f"k{i}", i * 0.12) for i in range(50))


# --- Lokal (sunum modu) -----------------------------------------------------
def test_demo_imzalari():
    assert imza_bul(["cmd", "/c", "simulator\\lokal_saldiri.bat"])
    assert imza_bul(["cmd", "/c", "veri_paketleme.bat"])
    assert imza_bul(["cmd", "/c", "dir"]) is None


def test_programin_kendi_yolu_hedefleme_sayilmaz():
    exe = os.path.join(PROTECTED_DIR, "simulator", "winword.exe")
    assert not process.korunan_dizini_hedefliyor([exe, "/c", "powershell -c Start-Sleep 1"])
    assert process.korunan_dizini_hedefliyor([exe, "/c", "type " + os.path.join(PROTECTED_DIR, "x.txt")])
