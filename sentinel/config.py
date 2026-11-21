"""Sentinel genel ayarlari: tum moduller yollari ve esikleri buradan okur."""
import logging
import os

# Proje kok klasoru (sentinel/ paketinin bir ustu)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "sentinel_logs.db")

# Korunan dizin: bu klasoru hedef alan arsivleme/erisim davranislari izlenir
PROTECTED_DIR = BASE_DIR

# --- Ag: honeypot -----------------------------------------------------------
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = 9999
HONEYPOT_IP_COOLDOWN = 5.0      # Ayni IP icin kac saniyede bir alarm uretilir

# --- Ag: SYN port tarama dedektoru (scapy + Npcap) --------------------------
SCAN_WINDOW_SECONDS = 10.0       # Bu pencerede...
SCAN_PORT_THRESHOLD = 15         # ...bu kadar FARKLI porta SYN gelirse tarama sayilir
SCAN_IP_COOLDOWN = 30.0

# --- Veri sizdirma sensoru --------------------------------------------------
EXFIL_SAMPLE_SECONDS = 5.0
EXFIL_UPLOAD_BYTES_PER_SEC = 5 * 1024 * 1024   # 5 MB/s ustu giden trafik...
EXFIL_SUSTAINED_SAMPLES = 3                    # ...art arda bu kadar ornek surerse alarm
EXFIL_ALERT_COOLDOWN = 60.0

# --- Karar motoru -----------------------------------------------------------
EVENT_WINDOW_SECONDS = 10        # Olay korelasyon penceresi
KILL_CHAIN_THRESHOLD = 80.0      # Bu skor ve ustu: surec imha + oturum kilidi
LOCK_COOLDOWN_SECONDS = 3

# --- Klavye (BadUSB) sensoru ------------------------------------------------
KEY_FAST_INTERVAL = 0.02         # Iki tus arasi bu sureden kisaysa "insanustu"
KEY_FAST_COUNT = 5               # Ard arda bu kadar hizli FARKLI tus -> alarm


def get_logger(name):
    """Her modul icin ayni formatta konsol loglayici dondurur."""
    logger = logging.getLogger(f"sentinel.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
