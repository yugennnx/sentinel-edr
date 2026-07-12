import sqlite3
import time
from datetime import datetime

DB_NAME = "sentinel_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Eşzamanlı okuma/yazma yapabilmek için WAL modu aktif edildi
    cursor.execute('PRAGMA journal_mode=WAL;')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            layer TEXT,
            event_type TEXT,
            confidence REAL,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def db_writer_worker(db_queue):
    init_db()
    print("[*] Veritabani Koprusu Aktif. Loglar diske yaziliyor...")
    
    conn = sqlite3.connect(DB_NAME, timeout=10)
    cursor = conn.cursor()
    
    while True:
        try:
            if not db_queue.empty():
                item = db_queue.get()
                
                if item == "STOP":
                    break
                
                katman, olay_tipi, guven, mesaj = item
                zaman_damgasi = datetime.now().strftime("%H:%M:%S")
                
                cursor.execute('''
                    INSERT INTO logs (timestamp, layer, event_type, confidence, message)
                    VALUES (?, ?, ?, ?, ?)
                ''', (zaman_damgasi, katman, olay_tipi, guven, mesaj))
                conn.commit()
            else:
                time.sleep(0.1)
        except Exception as e:
            pass
            
    conn.close()
    print("[-] Veritabani baglantisi kapatildi.")