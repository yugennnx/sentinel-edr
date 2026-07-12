import time
import re
import psutil
import ctypes
import math
import subprocess

def guvenli_surec_oldur(hedef_pid, hedef_ctime):
    try:
        p = psutil.Process(int(hedef_pid))
        if str(p.create_time()) == str(hedef_ctime):
            p.kill() 
            print(f"[-] Zararli surec (PID: {hedef_pid}) AI tarafindan basariyla imha edildi.")
    except psutil.NoSuchProcess:
        pass 
    except Exception:
        pass

# =========================================================
# OTONOM IPS: DİNAMİK GÜVENLİK DUVARI ENGELLEMESİ
# =========================================================
def dinamik_ip_engelle(saldirgan_ip):
    # Sistemin kendi kendini (Localhost) engellemesini fiziksel olarak yasaklıyoruz.
    if saldirgan_ip in ["127.0.0.1", "localhost"]:
        print(f"[-] Uyari: {saldirgan_ip} (Localhost) sistem kararliligi icin engellenemez.")
        return
        
    kural_adi = f"Sentinel_Block_{saldirgan_ip}"
    komut = f'netsh advfirewall firewall add rule name="{kural_adi}" dir=in action=block remoteip={saldirgan_ip}'
    
    try:
        subprocess.run(komut, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[!] IPS DEVREDE: {saldirgan_ip} IP Adresi Guvenlik Duvarinda KARA LISTEYE alindi!")
    except Exception as e:
        print(f"[!] Firewall kurali eklenemedi: {e}")

# =========================================================
# YAPAY ZEKA: BULANIK MANTIK (FUZZY LOGIC) MOTORU
# =========================================================
def bulanik_mantik_hesapla(olaylar):
    taban_risk = 0.0
    
    if "KEYBOARD_ANOMALY" in olaylar: taban_risk += 40.0
    if "USB_INSERTED" in olaylar: taban_risk += 20.0
    if "SUSPICIOUS_PROCESS" in olaylar: taban_risk += 60.0
    if "NETWORK_SCAN" in olaylar: taban_risk += 75.0 
    if "LOCAL_FILE_ACCESS" in olaylar: taban_risk += 85.0 
    
    carpan = 1.0
    if "USB_INSERTED" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.4
    if "SUSPICIOUS_PROCESS" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.5
    if "LOCAL_FILE_ACCESS" in olaylar and "DATA_EXFILTRATION" in olaylar: carpan += 0.6
    if "LOCAL_FILE_ACCESS" in olaylar and "NETWORK_SCAN" in olaylar: carpan += 0.6
        
    if len(olaylar) >= 3: carpan += 0.3
        
    ham_skor = taban_risk * carpan
    if ham_skor == 0: return 0.0
    nihai_risk = 100 / (1 + math.exp(-0.05 * (ham_skor - 50)))
    return round(nihai_risk, 2)

def ai_fusion_worker(queue):
    print("[*] Baglam Farkindalikli Karar Motoru (Monol) Baslatildi. Otonom Savunma Aktif.")
    
    olay_gecmisi = [] 
    kilit_bekleme_suresi = 0  
    
    while True:
        su_an = time.time()
        
        # 1. HIZLI TAHLİYE (FAST-DRAIN)
        if su_an < kilit_bekleme_suresi:
            while not queue.empty():
                queue.get() 
            time.sleep(0.5)
            continue
            
        # 2. DARBOĞAZ İPTALİ
        while not queue.empty():
            katman, olay_tipi, guven, mesaj = queue.get()
            olay_gecmisi.append({"zaman": su_an, "tip": olay_tipi, "mesaj": mesaj})
            
        olay_gecmisi = [olay for olay in olay_gecmisi if su_an - olay["zaman"] <= 10]
        
        benzersiz_olaylar = set([olay["tip"] for olay in olay_gecmisi])
        if len(benzersiz_olaylar) == 0:
            time.sleep(0.5)
            continue
            
        toplam_risk = bulanik_mantik_hesapla(benzersiz_olaylar)

        # PROTOKOL 1: AĞ SAVUNMASI (DİNAMİK IPS)
        if "NETWORK_SCAN" in benzersiz_olaylar:
            print("\n" + "*"*55)
            print("[!] AG TAARRUZU (PORT SCAN/SYN FLOOD) TESPIT EDILDI")
            for olay in olay_gecmisi:
                if olay["tip"] == "NETWORK_SCAN":
                    match = re.search(r"Kaynak IP:\s*([\d\.]+)", olay["mesaj"])
                    if match:
                        saldirgan_ip = match.group(1)
                        print(f"[-] Saldirgan IP ({saldirgan_ip}) izole ediliyor...")
                        dinamik_ip_engelle(saldirgan_ip)
            print("*"*55 + "\n")
            olay_gecmisi.clear() 
            continue 
        
        # PROTOKOL 2: MUTLAK İDAM (Fiziksel / Donanımsal)
        if "KEYBOARD_ANOMALY" in benzersiz_olaylar:
            print("\n" + "="*55)
            print("[!!!] DONANIMSAL SPOOFING: İNSANÜSTÜ KLAVYE HIZI [!!!]")
            print("[-] Sistem derhal korumaya aliniyor (Oturum Kilitlendi).")
            ctypes.windll.user32.LockWorkStation()
            olay_gecmisi.clear()
            kilit_bekleme_suresi = su_an + 3 
            print("="*55 + "\n")
            continue 
        
        # PROTOKOL 3: GÖLGE MÜDAHALE (Sessiz Savunma)
        if "USB_INSERTED" not in benzersiz_olaylar:
            if "SUSPICIOUS_PROCESS" in benzersiz_olaylar and "DATA_EXFILTRATION" in benzersiz_olaylar and "LOCAL_FILE_ACCESS" not in benzersiz_olaylar:
                print("\n" + "*"*55)
                print("[!] UZAKTAN SALDIRI TESPITI (Truva Ati Suphesi)")
                print(f"[>] AI Risk Skoru: {toplam_risk}")
                print("[-] Bilgisayar kilitlenmeyecek ancak kacak surec sessizce oldurulecek.")
                for olay in olay_gecmisi:
                    if olay["tip"] == "SUSPICIOUS_PROCESS":
                        match = re.search(r"\(PID:\s*(\d+),\s*CTIME:\s*([\d\.]+)\)", olay["mesaj"])
                        if match: guvenli_surec_oldur(match.group(1), match.group(2))
                print("*"*55 + "\n")
                olay_gecmisi.clear() 
                continue 
                            
        # PROTOKOL 4: KILL-CHAIN (Siber-Fiziksel İnfaz / Kilitlenme)
        if toplam_risk >= 80.0:
            print("\n" + "="*55)
            print("[!!!] KILL-CHAIN: KESINLESMIŞ SİBER-FİZİKSEL SIZMA VEYA LOKAL İHLAL [!!!]")
            print(f"[>] Hesaplanmis AI (Fuzzy Logic) Skoru: {toplam_risk}")
            print("[>] SAVUNMA PROTOKOLÜ DEVREDE: Imha Basliyor...")
            
            for olay in olay_gecmisi:
                if olay["tip"] in ["SUSPICIOUS_PROCESS", "LOCAL_FILE_ACCESS"]:
                    match = re.search(r"\(PID:\s*(\d+),\s*CTIME:\s*([\d\.]+)\)", olay["mesaj"])
                    if match: guvenli_surec_oldur(match.group(1), match.group(2))
            
            print("[-] Sistem korumaya aliniyor (Oturum Kilitlendi).")
            ctypes.windll.user32.LockWorkStation()
            
            olay_gecmisi.clear()
            kilit_bekleme_suresi = su_an + 3 
            
            print("[*] Mudahale tamamlandi. Sistem yeni saldirilara hazir.")
            print("="*55 + "\n")
        
        time.sleep(0.5)
