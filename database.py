import queue as queue_mod
import sqlite3
from datetime import datetime

from config import DB_PATH, get_logger

DB_NAME = DB_PATH  # Geriye donuk uyumluluk
log = get_logger("database")


def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
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
    finally:
        conn.close()


def db_writer_worker(db_queue, db_path=DB_PATH):
    init_db(db_path)
    log.info("Veritabani koprusu aktif. Loglar diske yaziliyor: %s", db_path)

    conn = sqlite3.connect(db_path, timeout=10)
    cursor = conn.cursor()

    try:
        while True:
            try:
                item = db_queue.get(timeout=1)
            except queue_mod.Empty:
                continue

            if item == "STOP":
                break

            try:
                katman, olay_tipi, guven, mesaj = item
            except (TypeError, ValueError):
                log.warning("Gecersiz kayit atlandi: %r", item)
                continue

            # Tarih de yaziliyor: gun degisince siralama ve grafikler bozulmasin
            zaman_damgasi = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                cursor.execute('''
                    INSERT INTO logs (timestamp, layer, event_type, confidence, message)
                    VALUES (?, ?, ?, ?, ?)
                ''', (zaman_damgasi, str(katman), str(olay_tipi), float(guven), str(mesaj)))
                conn.commit()
            except sqlite3.Error as e:
                log.error("Log yazilamadi: %s", e)
    finally:
        conn.close()
        log.info("Veritabani baglantisi kapatildi.")
