import subprocess
import sys
import time

print("[*] SENTINEL Sistemi Baslatiliyor...")
print("[*] Lutfen arayuzun acilmasini bekleyin...")

# 1. HATA DÜZELTİLDİ: Senin orijinal arka plan motorunu (controller.py) baslat!
motor = subprocess.Popen([sys.executable, "controller.py"])

# Veritabaninin ayaga kalkmasi (tabloların olusmasi) icin 3 saniye bekle
time.sleep(3) 

# 2. Senin alıştığın Görsel Arayüzü (arayuz.py) baslat
arayuz = subprocess.Popen([sys.executable, "arayuz.py"])

# Kullanici arayuz penceresini acik tuttugu surece sistemi bekle
arayuz.wait()

# --- KAPANIS PROSEDURU ---
print("\n[!] Arayuz kapatildi. Arka plan koruma motorlari durduruluyor...")
motor.terminate()
print("[-] SENTINEL guvenle kapatildi.")