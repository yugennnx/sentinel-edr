import os
import subprocess
import sys
import time

import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def surec_agacini_kapat(popen, timeout=5):
    """Ana sureci VE alt sureclerini kapatir.

    Popen.terminate() Windows'ta sadece ana sureci oldurur; controller'in
    actigi sensorler (klavye dinleyici, honeypot portu) yetim kalip calismaya
    devam ederdi.
    """
    try:
        ana = psutil.Process(popen.pid)
    except psutil.NoSuchProcess:
        return
    surecler = ana.children(recursive=True) + [ana]
    for p in surecler:
        try:
            p.terminate()
        except psutil.NoSuchProcess:
            pass
    _, hayatta = psutil.wait_procs(surecler, timeout=timeout)
    for p in hayatta:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass


print("[*] SENTINEL Sistemi Baslatiliyor...")
print("[*] Lutfen arayuzun acilmasini bekleyin...")

motor = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "controller.py")], cwd=BASE_DIR)

# Veritabaninin ayaga kalkmasi (tablolarin olusmasi) icin bekle
time.sleep(3)

arayuz = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "arayuz.py")], cwd=BASE_DIR)

try:
    arayuz.wait()
finally:
    print("\n[!] Arayuz kapatildi. Arka plan koruma motorlari durduruluyor...")
    surec_agacini_kapat(motor)
    print("[-] SENTINEL guvenle kapatildi.")
