import sys
import time

def simule_et():
    print("="*50)
    print(">>> SENTINEL ETIK TEST AJANI BASLATILDI <<<")
    print("="*50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "-etik-test":
        print("[!] Sahte zararli parametre ile calisildi.")
        print("[!] Davranissal kural ihlali simule ediliyor...")
        print("[*] SENTINEL EDR'in bu sureci bulup imha etmesi bekleniyor...")
        
        # Sistemin ajanı avlaması için 15 saniyelik bir pencere
        for i in range(15, 0, -1):
            print(f"Stabil kalinan sure: {i} saniye...")
            time.sleep(1)
            
        print("[-] HATA: Sentinel basarisiz oldu. Surec olmedi.")
    else:
        print("Lutfen betigi '-etik-test' parametresi ile baslatin.")

if __name__ == "__main__":
    simule_et()