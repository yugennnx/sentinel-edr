import os
import sys

# Betik dogrudan calistirildiginda (streamlit run / python) proje kokunu import yoluna ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import tkinter as tk
import sqlite3
import datetime

from sentinel.config import DB_PATH as DB_NAME

def fetch_data():
    try:
        # Timeout 10 saniyeye çıkarıldı (Kilitlenmeyi önler)
        conn = sqlite3.connect(DB_NAME, timeout=10)
        cursor = conn.cursor()
        
        # DÜZELTME: Veritabanı motoru ile tam uyumlu tablo (logs) ve kolon (layer) isimleri
        cursor.execute("SELECT timestamp, layer, event_type FROM logs ORDER BY id DESC LIMIT 20")
        
        rows = cursor.fetchall()
        conn.close()
        return rows, None
    except Exception as e:
        return None, str(e)

def update_gui():
    rows, error = fetch_data()
    
    log_box.config(state=tk.NORMAL)
    
    if error:
        # Eğer kilitlenme yaşanırsa sessizce çökmek yerine ekrana kırmızı hata basar
        log_box.delete('1.0', tk.END)
        log_box.insert(tk.END, f"HATA: Veritabanına ulaşılamadı!\nDetay: {error}\nSistem tekrar deniyor...")
        status_label.config(text="[!] VERİTABANI KİLİTLİ / BEKLENİYOR", fg="yellow")
    elif rows is not None:
        log_box.delete('1.0', tk.END)
        cyber_count = 0
        phys_count = 0
        
        for row in rows:
            zaman, modul, olay = row
            log_box.insert(tk.END, f"[{zaman}] {modul} - {olay}\n")
            
            # Füzyon AI için sayaçlar
            if modul == 'CYBER':
                cyber_count += 1
            elif modul == 'PHYSICAL':
                phys_count += 1
                
        # Tehdit Skoru Kararı
        if cyber_count > 0 and phys_count > 0:
            status_label.config(text="[!!!] KRİTİK FÜZYON ALARMI (BadUSB Şüphesi)", fg="red")
        elif cyber_count > 0 or phys_count > 0:
            status_label.config(text="[!] UYARI: Tekil Katman İhlali", fg="orange")
        else:
            status_label.config(text="[+] SİSTEM GÜVENDE: Anomali Yok", fg="#00ff00")
            
    log_box.config(state=tk.DISABLED)
    
    # Arayüzün yaşayıp yaşamadığını gösteren canlı saat
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    time_label.config(text=f"Son Güncelleme: {current_time}")
    
    # 2 saniyede bir kendini tekrar çağırır
    root.after(2000, update_gui)

# --- ARAYÜZ (GUI) TASARIMI ---
root = tk.Tk()
root.title("SENTINEL - Siber-Fiziksel Komuta Merkezi")
root.geometry("750x550")
root.configure(bg="#0a0a0a") 

# Başlık
header = tk.Label(root, text="🛡️ SENTINEL AKTİF İZLEME 🛡️", font=("Courier", 18, "bold"), bg="#0a0a0a", fg="#00ff00")
header.pack(pady=10)

# Tehdit Durumu Bildirgesi
status_label = tk.Label(root, text="Sistem Başlatılıyor...", font=("Courier", 14, "bold"), bg="#0a0a0a", fg="white")
status_label.pack(pady=10)

# Canlı Saat Sayacı
time_label = tk.Label(root, text="Son Güncelleme: Bekleniyor...", font=("Courier", 10), bg="#0a0a0a", fg="gray")
time_label.pack()

# Log Ekranı
log_box = tk.Text(root, height=20, width=85, bg="#000000", fg="#00ff00", font=("Consolas", 10))
log_box.pack(padx=20, pady=10)
log_box.config(state=tk.DISABLED)

update_gui()
root.mainloop()