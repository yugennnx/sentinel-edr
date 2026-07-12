import time
import wmi
import pythoncom
import psutil
import threading
import socket
from pynput import keyboard
from scapy.all import sniff, IP, TCP
from scapy.config import conf

# ==============================================================================
# 1. FİZİKSEL KATMAN SENSÖRÜ
# ==============================================================================
def physical_layer_worker(queue):
    pythoncom.CoInitialize()
    c = wmi.WMI()
    
    known_usb = {usb.DeviceID for usb in c.Win32_USBHub()}
    last_press_time = [time.time()]
    son_alarm_zamani = [0.0]
    hizli_tus_sayisi = [0] 

    def on_press(key):
        current_time = time.time()
        diff = current_time - last_press_time[0]
        last_press_time[0] = current_time
        
        if diff < 0.02:
            hizli_tus_sayisi[0] += 1
        else:
            hizli_tus_sayisi[0] = 0
            
        if hizli_tus_sayisi[0] > 5 and (current_time - son_alarm_zamani[0]) > 2.0:  
            queue.put(("PHYSICAL", "KEYBOARD_ANOMALY", 0.9, "BadUSB Suphesi: Kesintisiz hizli tuslama"))
            son_alarm_zamani[0] = current_time
            hizli_tus_sayisi[0] = 0

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    
    try:
        while True:
            time.sleep(5) 
            current_usb = {usb.DeviceID for usb in c.Win32_USBHub()}
            
            new_usb = current_usb - known_usb
            if new_usb:
                for dev in new_usb:
                    queue.put(("PHYSICAL", "USB_INSERTED", 0.6, f"Yeni Cihaz: {dev}"))
                known_usb = current_usb 
                
            removed_usb = known_usb - current_usb
            if removed_usb:
                for dev in removed_usb:
                    queue.put(("PHYSICAL", "USB_REMOVED", 0.1, f"Cihaz Cikarildi: {dev}"))
                known_usb = current_usb
                
    except Exception as e:
        queue.put(("PHYSICAL", "ERROR", 1.0, str(e)))
    finally:
        listener.stop()
        pythoncom.CoUninitialize()

# ==============================================================================
# 2. SİBER KATMAN SENSÖRÜ (EDR)
# ==============================================================================
def cyber_layer_worker(queue):
    time.sleep(3)
    print("[*] Siber Katman (EDR Modu) Aktif. MITRE ATT&CK Davranissal Analiz Basladi...")
    
    raporlanan_pidler = set()
    tehlikeli_ebeveynler = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'acrobat.exe']
    hedef_kabuklar = ['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe']
    zararli_parametreler = ['-enc', 'bypass', 'hidden', 'downloadstring', 'invoke-webrequest', 'bitsadmin', 'certutil']

    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time']):
                try:
                    pid = proc.info['pid']
                    name = str(proc.info['name']).lower()

                    if pid in raporlanan_pidler:
                        continue

                    if name in hedef_kabuklar:
                        cmdline = proc.info.get('cmdline')
                        
                        if cmdline:
                            cmd_str = " ".join(cmdline).lower()
                            if "streamlit" in cmd_str:
                                continue
                        
                        ppid = proc.info.get('ppid')
                        tespit_nedeni = []

                        if ppid:
                            try:
                                parent = psutil.Process(ppid)
                                parent_name = parent.name().lower()
                                if parent_name in tehlikeli_ebeveynler:
                                    tespit_nedeni.append(f"Zararli Parent-Child Baglantisi ({parent_name} -> {name})")
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        if cmdline:
                            for param in zararli_parametreler:
                                if param in cmd_str:
                                    tespit_nedeni.append(f"Kritik Payload Parametresi Yakalandi ({param})")
                                    break 

                        try:
                            connections = proc.connections()
                            for conn in connections:
                                if conn.status == 'ESTABLISHED' and conn.raddr:
                                    if conn.raddr.port not in [80, 443] and conn.raddr.ip != '127.0.0.1':
                                        tespit_nedeni.append(f"Ters Baglanti Tespiti -> Hedef: {conn.raddr.ip}:{conn.raddr.port}")
                                        break
                        except psutil.AccessDenied:
                            pass 

                        if len(tespit_nedeni) > 0:
                            ctime = proc.info.get('create_time', 0.0)
                            detay = f"EDR: {name} (PID: {pid}, CTIME: {ctime}) | Neden: {' | '.join(tespit_nedeni)}"
                            queue.put(("CYBER", "SUSPICIOUS_PROCESS", 0.99, detay))
                            raporlanan_pidler.add(pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        time.sleep(2) 



# ==============================================================================
# 3. AĞ KATMANI SENSÖRÜ (Bal Küpü / Honeypot Modu - %100 GARANTİLİ)
# ==============================================================================
def network_layer_worker(queue):
    print("[*] Ag Katmani Sensoru (Honeypot) Aktif. Sahte Kapı (Port 9999) Acildi...")
    
    try:
        # En basit ağ dinleyicisi (Yönetici izni gerektirmez)
        tuzak = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tuzak.bind(('0.0.0.0', 9999)) 
        tuzak.listen(1)
        
        while True:
            baglanti, adres = tuzak.accept()
            saldirgan_ip = adres[0]
            
            # Saldırgan sahte kapıya dokunduğu an AI'yi ateşle
            queue.put(("NETWORK", "NETWORK_SCAN", 0.99, f"Ag Taramasi Tespiti -> Kaynak IP: {saldirgan_ip}"))
            
            baglanti.close()
            time.sleep(1) # Ekrana spam yapmasın diye 1 saniye bekle
            
    except Exception as e:
        print(f"[!] Sensor Hatasi: {e}")

# ==============================================================================
# 4. LOKAL DAVRANIŞ ANALİZİ (SUNUM MODU V2)
# ==============================================================================
def local_behavior_worker(queue):
    print("[*] Lokal Davranis Analizcisi (LBA) Aktif. Sunum Modu Devrede...")

    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    p_name = proc.info.get('name', '').lower()
                    
                    if p_name != "cmd.exe":
                        continue

                    cmdline = proc.info.get('cmdline')
                    if not cmdline:
                        continue

                    cmd_str = " ".join(cmdline).lower()

                    if "lokal_saldiri" in cmd_str:
                        ctime = proc.info.get('create_time', 0.0)
                        detay = f"Lokal Ihlal (Casus Yazilim): Sızma Tespit Edildi (PID: {proc.info['pid']}, CTIME: {ctime}) -> Sentinel Hedeflendi"
                        queue.put(("CYBER", "LOCAL_FILE_ACCESS", 0.99, detay))

                    elif "veri_paketleme" in cmd_str:
                        ctime = proc.info.get('create_time', 0.0)
                        detay = f"Lokal Ihlal (Veri Paketleme/Dripping): Arsivleme Tespit Edildi (PID: {proc.info['pid']}, CTIME: {ctime}) -> Sentinel Kopyalaniyor"
                        queue.put(("CYBER", "LOCAL_FILE_ACCESS", 0.99, detay))

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        
        time.sleep(1)
