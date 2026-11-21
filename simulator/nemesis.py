"""NEMESIS: Sentinel icin saldiri simulatoru.

YALNIZCA kendi bilgisayarinizda, Sentinel'in tespitlerini gostermek icin kullanin.
Senaryolar zararsizdir: sistem araclarinin kopyalari kisa sure bekleyip kapanir,
dis baglanti denemeleri belgeleme amacli (TEST-NET) bir adrese yapilir.
"""
import tkinter as tk
import subprocess
import threading
import socket
import shutil
import os
import tempfile

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

# Sahnede görsel şov yapmak ve arka plan çökmelerini önlemek için araç yolları
CASUS_EXE = os.path.join(SIM_DIR, "siber_casus.exe")
HIRSIZ_EXE = os.path.join(SIM_DIR, "veri_hirsizi.exe")

def araclari_hazirla():
    cmd_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    try:
        # CMD'nin kopyasi sahte ajan olarak yaratilir (Asla cokmez)
        if not os.path.exists(CASUS_EXE): shutil.copy2(cmd_path, CASUS_EXE)
        if not os.path.exists(HIRSIZ_EXE): shutil.copy2(cmd_path, HIRSIZ_EXE)
    except Exception as e:
        print("Arac hazirlama hatasi:", e)

def ag_taramasi_yap():
    # Sentinel'in tuzak kapısına (Bal Küpü - Port 9999) direkt saldırı
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect_ex((HEDEF_IP, 9999))
        s.close()
    except: pass

def execute_attack(attack_type):
    araclari_hazirla()
    
    # Sahnede yeni bir terminal penceresi açma bayrağı (Arka plan çökmelerini engeller)
    CREATE_NEW_CONSOLE = 0x00000010 

    if attack_type == "NMAP":
        status_label.config(text="[+] DURUM: Ag Kesfi (Nmap SYN Scan) Baslatildi...", fg="#00FFFF")
        threading.Thread(target=ag_taramasi_yap).start()

    elif attack_type == "TRUVA":
        status_label.config(text="[+] DURUM: Truva Ati (C2) Baglaniyor...", fg="#00FF00")
        cmd = f'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$client = New-Object System.Net.Sockets.TcpClient(\'{KALI_IP}\', 9999); Start-Sleep -s 10; $client.Close()"'
        subprocess.Popen(cmd, shell=True)

    elif attack_type == "MAKRO":
        status_label.config(text="[+] DURUM: Oltalama (Makro) Devrede...", fg="#FF00FF")
        cmd = 'copy "%SystemRoot%\\System32\\cmd.exe" winword.exe /Y > nul && winword.exe /c "powershell.exe -WindowStyle Hidden -Command Start-Sleep -s 10"'
        subprocess.Popen(cmd, shell=True, cwd=SIM_DIR)

    elif attack_type == "FILELESS":
        status_label.config(text="[+] DURUM: Dosyasiz Indirme (LoTL) Calistirildi...", fg="#00BFFF")
        cmd = f'powershell.exe -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://example.com -OutFile \'{TEST_CIKTISI}\'; Start-Sleep -s 10"'
        subprocess.Popen(cmd, shell=True)

    elif attack_type == "LOCAL":
        status_label.config(text="[+] DURUM: Lokal Ihlal (Gorsel Casus) Devrede...", fg="#FF8C00")
        # Ekranda KIRMIZI renkli gercek bir korsan terminali firlatir. AI onu 15 saniye icinde gorecek.
        cmd = f'"{CASUS_EXE}" /c "color 4c & title SIBER CASUS - SIZMA BASARILI & echo [!] SISTEME SIZILDI. & echo [^>] Hedeflenen Dizin: {HEDEF_PROJE} & echo [*] Kritik Sifreler Cekiliyor... Lutfen Bekleyin. & ping 127.0.0.1 -n 15 > nul"'
        subprocess.Popen(cmd, creationflags=CREATE_NEW_CONSOLE)

    elif attack_type == "DRIPPING":
        status_label.config(text="[+] DURUM: Veri Paketleme (Gorsel Hirsiz) Devrede...", fg="#FFD700")
        # Ekranda SARI renkli gercek bir korsan terminali firlatir.
        cmd = f'"{HIRSIZ_EXE}" /c "color 60 & title VERI HIRSIZI - PAKETLEME & echo [!] VERI SIZINTISI BASLADI. & echo [^>] Kaynak Merkez: {HEDEF_PROJE} & echo [*] Tum projeler arsivleniyor (Dripping)... & ping 127.0.0.1 -n 15 > nul"'
        subprocess.Popen(cmd, creationflags=CREATE_NEW_CONSOLE)

    elif attack_type == "EXFIL":
        status_label.config(text="[+] DURUM: Gizli Veri Paketleme (Compress-Archive) Devrede...", fg="#FF4500")
        # Gizli PowerShell (SUSPICIOUS_PROCESS) + korunan dizinin arsivlenmesi (DATA_EXFILTRATION)
        # -> Sentinel'in 'golge mudahale' protokolu sureci sessizce oldurmeli. Zip sonunda silinir.
        kaynak = os.path.join(HEDEF_PROJE, "sentinel")
        cmd = (f"powershell.exe -WindowStyle Hidden -Command \"Compress-Archive -Path '{kaynak}' "
               f"-DestinationPath '{SIZINTI_ZIP}' -Force; Start-Sleep -s 15; Remove-Item '{SIZINTI_ZIP}'\"")
        subprocess.Popen(cmd, shell=True)

    root.after(4000, lambda: status_label.config(text="[*] DURUM: Hedef Bekleniyor...", fg="#FF003C"))

# ==========================================
# ARAYÜZ TASARIMI
# ==========================================
root = tk.Tk()
root.title("NEMESIS | Saldiri Arayuzu")
root.geometry("600x600")
root.configure(bg="#050505")

header = tk.Label(root, text="☠️ NEMESIS SALDIRI AĞI ☠️", font=("Courier", 18, "bold"), bg="#050505", fg="#FF003C")
header.pack(pady=15)

btn_nmap = tk.Button(root, text="1. AĞ TARAMASI (Nmap / Kesif)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#00FFFF", activebackground="#00FFFF", width=50, command=lambda: execute_attack("NMAP"))
btn_nmap.pack(pady=6)

btn_truva = tk.Button(root, text="2. TRUVA ATI (C2 Sizmasi)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#00FF00", activebackground="#00FF00", width=50, command=lambda: execute_attack("TRUVA"))
btn_truva.pack(pady=6)

btn_makro = tk.Button(root, text="3. OLTALAMA (Zararli Word Makrosu)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#FF00FF", activebackground="#FF00FF", width=50, command=lambda: execute_attack("MAKRO"))
btn_makro.pack(pady=6)

btn_fileless = tk.Button(root, text="4. DOSYASIZ İNDİRME (Living off the Land)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#00BFFF", activebackground="#00BFFF", width=50, command=lambda: execute_attack("FILELESS"))
btn_fileless.pack(pady=6)

btn_local = tk.Button(root, text="5. LOKAL İHLAL (Casus Sızması)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#FF8C00", activebackground="#FF8C00", width=50, command=lambda: execute_attack("LOCAL"))
btn_local.pack(pady=6)

btn_drip = tk.Button(root, text="6. VERİ PAKETLEME (Zipleme Sızıntısı)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#FFD700", activebackground="#FFD700", width=50, command=lambda: execute_attack("DRIPPING"))
btn_drip.pack(pady=6)

btn_exfil = tk.Button(root, text="7. GİZLİ VERİ SIZDIRMA (Compress-Archive)", font=("Consolas", 11, "bold"), bg="#1a0000", fg="#FF4500", activebackground="#FF4500", width=50, command=lambda: execute_attack("EXFIL"))
btn_exfil.pack(pady=6)

status_label = tk.Label(root, text="[*] DURUM: Hedef Bekleniyor...", font=("Courier", 11), bg="#050505", fg="#FF003C")
status_label.pack(pady=20)

root.mainloop()