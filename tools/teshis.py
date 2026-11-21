import wmi
import psutil
import time

print("===" * 15)
print(" SENSÖR KÖRLÜK TESTİ (DİAGNOSTİK) ")
print("===" * 15)

print("\n[1] Siber Katman (psutil) test ediliyor...")
try:
    pids = psutil.pids()
    print(f" -> Başarılı! Sistemde {len(pids)} aktif işlem (process) okundu.")
except Exception as e:
    print(f" -> HATA: psutil okuyamıyor! Detay: {e}")

print("\n[2] Fiziksel Katman (WMI/USB) test ediliyor...")
c = wmi.WMI()
baslangic_usb = c.Win32_USBHub()
print(f" -> Başlangıçta algılanan USB Aygıt Sayısı: {len(baslangic_usb)}")

print("\n*** LÜTFEN ŞİMDİ USB BELLEĞİ TAKIN ***")
print("(Sistemin aygıtı tanıması için 10 saniye bekliyor...)")

for i in range(10, 0, -1):
    print(f"{i}...", end=" ", flush=True)
    time.sleep(1)

bitis_usb = c.Win32_USBHub()
print(f"\n\n -> Son durumda algılanan USB Aygıt Sayısı: {len(bitis_usb)}")

if len(bitis_usb) > len(baslangic_usb):
    print("\n[+] SONUÇ: FİZİKSEL SENSÖR ÇALIŞIYOR. (USB'yi gördü)")
elif len(bitis_usb) == len(baslangic_usb):
    print("\n[-] SONUÇ: SENSÖR KÖR! (USB takıldı ama Win32_USBHub bunu algılamadı)")
    print("Nedeni: USB belleğin Windows'ta 'Hub' olarak değil, 'Sabit Disk' olarak tanınıyor.")
else:
    print("\n[?] Beklenmeyen bir durum oluştu (Aygıt sayısı azaldı).")