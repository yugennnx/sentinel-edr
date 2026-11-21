import sqlite3

from config import DB_PATH

# Veritabanına salt okunur bağlan (çalışan sisteme dokunmaz)
try:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT id, timestamp, layer, event_type, confidence, message FROM logs ORDER BY id DESC LIMIT 15"
    ).fetchall()
    conn.close()
except sqlite3.Error as e:
    print(f"Veritabani okunamadi ({DB_PATH}): {e}")
    raise SystemExit(1)

print("\n" + "=" * 80)
print(" SENTINEL VERİTABANI - SON EKLENEN 15 KAYIT ".center(80, "="))
print("=" * 80)

if not rows:
    print("Veritabanı şu an boş. Hiç log kaydedilmemiş.")
else:
    for _id, zaman, modul, olay, skor, detay in rows:
        print(f"[{zaman}] Modül: {modul:<8} | Olay: {olay:<18} | Skor: {skor:<4} | Detay: {detay}")

print("=" * 80 + "\n")
