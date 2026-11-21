"""SENTINEL baslatici.

Kullanim:
    python run.py                 # Motor + masaustu arayuzu (Tkinter)
    python run.py --ui dashboard  # Motor + web paneli (Streamlit)
    python run.py --ui none       # Sadece motor (konsol)
"""
import argparse
import os
import subprocess
import sys
import time

import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(BASE_DIR, "sentinel", "ui")


def surec_agacini_kapat(popen, timeout=5):
    """Ana sureci VE alt sureclerini kapatir.

    Popen.terminate() Windows'ta sadece ana sureci oldurur; motorun actigi
    sensorler (klavye dinleyici, honeypot portu) yetim kalip calismaya devam ederdi.
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


def main():
    parser = argparse.ArgumentParser(description="SENTINEL siber-fiziksel EDR/IPS")
    parser.add_argument("--ui", choices=["desktop", "dashboard", "none"], default="desktop",
                        help="Motorla birlikte acilacak arayuz (varsayilan: desktop)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Tespit et ve karar ver ama mudahale etme (surec oldurme/IP engelleme/kilit yok)")
    args = parser.parse_args()
    if args.dry_run:
        os.environ["SENTINEL_DRY_RUN"] = "1"
        print("[!] DRY-RUN modu: mudahaleler sadece loglanacak.")

    print("[*] SENTINEL baslatiliyor...")
    motor = subprocess.Popen([sys.executable, "-m", "sentinel.controller"], cwd=BASE_DIR)

    if args.ui == "none":
        try:
            motor.wait()
        except KeyboardInterrupt:
            motor.wait()  # Ctrl+C motora da gider; motor kendi guvenli kapanisini yapar
        return

    time.sleep(3)  # Veritabani tablolarinin olusmasi icin
    if args.ui == "desktop":
        arayuz = subprocess.Popen([sys.executable, os.path.join(UI_DIR, "desktop.py")], cwd=BASE_DIR)
    else:
        arayuz = subprocess.Popen([sys.executable, "-m", "streamlit", "run",
                                   os.path.join(UI_DIR, "dashboard.py")], cwd=BASE_DIR)

    try:
        arayuz.wait()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[!] Arayuz kapatildi. Arka plan koruma motorlari durduruluyor...")
        surec_agacini_kapat(arayuz)
        surec_agacini_kapat(motor)
        print("[-] SENTINEL guvenle kapatildi.")


if __name__ == "__main__":
    main()
