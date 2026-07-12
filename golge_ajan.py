import time
import sys

def sinsi_operasyon():
    print("="*50)
    print(">>> GÖLGE AJAN: İÇERİ SIZILDI <<<")
    print("="*50)
    print("[!] Sistemde kalıcılık sağlanıyor...")
    
    # EDR Sensörünü kandırmak için sinsi bir argüman bekleyelim
    if len(sys.argv) > 1 and sys.argv[1] == "-hedef-ihlal":
        print("[!] Kritik payload tetiklendi. Veri kaçırma hazırlığı...")
        print("[*] Hedef: Yapay Zeka'nın bu süreci 20 saniye içinde bulup öldürmesi.")
        
        # Süreç hemen ölmesin diye 20 saniyelik bir hayatta kalma döngüsü
        for i in range(20, 0, -1):
            print(f"Hayatta kalınan süre: {i} saniye... (İnfaz bekleniyor)")
            time.sleep(1.0)
            
        print("[-] HATA: Sentinel başarısız oldu. Ajan hayatta kaldı.")
    else:
        print("[-] Operasyon iptal edildi. '-hedef-ihlal' parametresi eksik.")

if __name__ == "__main__":
    sinsi_operasyon()