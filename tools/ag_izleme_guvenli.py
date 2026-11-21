import threading
import time
from scapy.all import sniff, IP, TCP

# Bu değişken arka plandaki dinleyiciyi istediğimiz zaman durdurmamızı sağlayacak
dinleme_aktif = True

def guvenli_paket_analizi(paket):
    if paket.haslayer(IP) and paket.haslayer(TCP):
        kaynak = paket[IP].src
        hedef = paket[IP].dst
        boyut = len(paket)
        print(f"[GÜVENLİ İZLEME] TCP Akışı: {kaynak} --> {hedef} | Boyut: {boyut} bayt")

def arka_plan_dinleyici():
    print("[*] Arka plan iş parçacığı (Thread) başlatıldı. CPU güvende.")
    
    # filter="tcp": BPF filtresidir. Sadece TCP paketlerini donanım seviyesinde kabul eder.
    # stop_filter: Dinleme aktif değilse fonksiyonu güvenle sonlandırır, bellek sızıntısını önler.
    sniff(
        prn=guvenli_paket_analizi, 
        filter="tcp", 
        store=False, 
        stop_filter=lambda p: not dinleme_aktif
    )
    print("[*] Arka plan dinleyicisi güvenle durduruldu.")

# 1. ADIM: Ağ dinleyicisini ana koridordan ayırıp arka plana (Thread) yerleştiriyoruz
motor_thread = threading.Thread(target=arka_plan_dinleyici)
motor_thread.daemon = True # Bilgisayar kapatılırsa veya program durursa otomatik ölmesi için

# 2. ADIM: Arka plan sürecini tetikliyoruz
motor_thread.start()

# 3. ADIM: Ana koridor (Main Thread) tamamen özgür!
# Burada bilgisayarın donmadığını kanıtlamak için ana koridorda bir döngü çalıştırıyoruz
print("[+] Ana sistem tamamen özgür ve çalışıyor. 10 saniye boyunca test edilecek...\n")
for i in range(10):
    print(f"[Canlılık Kontrolü] Sistem Saati İşliyor, Donma Yok: Saniye {i+1}")
    time.sleep(1)

# 4. ADIM: Test bittiğinde arka planı güvenle kapatıyoruz
print("\n[-] Test süresi doldu. Arka plan kapatılıyor...")
dinleme_aktif = False