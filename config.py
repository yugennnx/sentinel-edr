"""Sentinel genel ayarlari: tum moduller yollari ve esikleri buradan okur."""
import logging
import os

# Proje klasoru: dosyalar hangi klasorden calistirilirsa calistirilsin ayni yeri gosterir.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentinel_logs.db")

# Ag tuzagi (honeypot)
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = 9999
HONEYPOT_IP_COOLDOWN = 5.0  # Ayni IP icin kac saniyede bir alarm uretilir

# Karar motoru
EVENT_WINDOW_SECONDS = 10   # Olay korelasyon penceresi
KILL_CHAIN_THRESHOLD = 80.0  # Bu skor ve ustu: surec imha + oturum kilidi
LOCK_COOLDOWN_SECONDS = 3

# Klavye (BadUSB) sensoru
KEY_FAST_INTERVAL = 0.02    # Iki tus arasi bu sureden kisaysa "insanustu"
KEY_FAST_COUNT = 5          # Ard arda bu kadar hizli FARKLI tus -> alarm


def get_logger(name):
    """Her modul icin ayni formatta konsol loglayici dondurur."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
