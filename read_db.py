import sqlite3

# Veritabanına bağlan
conn = sqlite3.connect("sentinel_logs.db")
cursor = conn.cursor()

# Tablodaki en son eklenen 15 olayı getir
cursor.execute("SELECT * FROM sensor_logs ORDER BY timestamp DESC LIMIT 15")
rows = cursor.fetchall()

print("\n" + "="*80)
print(" SENTINEL VERİTABANI - SON EKLENEN 15 KAYIT ".center(80, "="))
print("="*80)

if len(rows) == 0:
    print("Veritabanı şu an boş. Hiç log kaydedilmemiş.")
else:
    for row in rows:
        log_id = row[0]
        zaman = row[1]
        modul = row[2]
        olay = row[3]
        skor = row[4]
        detay = row[5]
        
        print(f"[{zaman}] Modül: {modul:<8} | Olay: {olay:<18} | Skor: {skor:<4} | Detay: {detay}")

print("="*80 + "\n")

conn.close()