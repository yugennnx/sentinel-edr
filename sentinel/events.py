"""Sensorlerin urettigi olay tipleri ve olay formati.

Her olay bir 4'lu demettir: (katman, olay_tipi, guven, mesaj)
Surec iceren olaylarin mesajinda "(PID: <pid>, CTIME: <create_time>)" bulunur;
karar motoru sureci bu bilgiyle guvenli sekilde hedefler.
"""

# Katmanlar
PHYSICAL = "PHYSICAL"
CYBER = "CYBER"
NETWORK = "NETWORK"

# Olay tipleri
KEYBOARD_ANOMALY = "KEYBOARD_ANOMALY"      # BadUSB: insanustu tuslama
USB_INSERTED = "USB_INSERTED"
USB_REMOVED = "USB_REMOVED"
SUSPICIOUS_PROCESS = "SUSPICIOUS_PROCESS"  # EDR davranis kurallari
LOCAL_FILE_ACCESS = "LOCAL_FILE_ACCESS"    # Korunan dizini hedef alan surec
DATA_EXFILTRATION = "DATA_EXFILTRATION"    # Veri paketleme / yuksek giden trafik
NETWORK_SCAN = "NETWORK_SCAN"              # Honeypot temasi veya SYN tarama
ERROR = "ERROR"

# Panelde kirmizi gosterilecek yuksek riskli olaylar
CRITICAL_EVENTS = [USB_INSERTED, DATA_EXFILTRATION, KEYBOARD_ANOMALY, LOCAL_FILE_ACCESS, NETWORK_SCAN]


def process_tag(pid, ctime):
    """Mesajlara eklenen, karar motorunun okudugu surec kimligi."""
    return f"(PID: {pid}, CTIME: {ctime or 0.0})"
