"""Fiziksel katman: USB cihaz takma/cikarma ve BadUSB (insanustu tuslama) tespiti."""
import time

from sentinel import events as ev
from sentinel.config import KEY_FAST_COUNT, KEY_FAST_INTERVAL, get_logger

log = get_logger("sensors.physical")


class KeystrokeAnalyzer:
    """Tus vuruslari arasindaki sureye bakarak BadUSB benzeri enjeksiyonu yakalar.

    Basili tutulan tusun otomatik tekrari (ayni tus) insan davranisidir ve sayilmaz.
    """

    def __init__(self, fast_interval=KEY_FAST_INTERVAL, fast_count=KEY_FAST_COUNT, cooldown=2.0):
        self.fast_interval = fast_interval
        self.fast_count = fast_count
        self.cooldown = cooldown
        self.last_time = None
        self.last_key = None
        self.fast_streak = 0
        self.last_alert = float("-inf")

    def feed(self, key, now):
        """Bir tus vurusu isler; alarm gerekiyorsa True dondurur."""
        gap = now - self.last_time if self.last_time is not None else float("inf")
        same_key = key == self.last_key
        self.last_time, self.last_key = now, key

        self.fast_streak = self.fast_streak + 1 if (gap < self.fast_interval and not same_key) else 0

        if self.fast_streak > self.fast_count and now - self.last_alert > self.cooldown:
            self.last_alert = now
            self.fast_streak = 0
            return True
        return False


def _usb_devices(c):
    """USB hub'lar + USB disk suruculeri.

    Bazi USB bellekler Win32_USBHub'da gorunmez, sadece disk olarak listelenir.
    """
    ids = {usb.DeviceID for usb in c.Win32_USBHub()}
    try:
        ids |= {d.PNPDeviceID for d in c.Win32_DiskDrive(InterfaceType="USB")}
    except Exception:  # Bazi sistemlerde sorgu desteklenmeyebilir
        pass
    return ids


def physical_layer_worker(queue):
    # Windows'a ozel kutuphaneler sadece bu surecte yuklenir
    import pythoncom
    import wmi
    from pynput import keyboard

    pythoncom.CoInitialize()
    c = wmi.WMI()
    analyzer = KeystrokeAnalyzer()

    def on_press(key):
        if analyzer.feed(key, time.time()):
            queue.put((ev.PHYSICAL, ev.KEYBOARD_ANOMALY, 0.9, "BadUSB Suphesi: Kesintisiz hizli tuslama"))

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    known = _usb_devices(c)
    log.info("Fiziksel katman aktif (%d USB cihazi biliniyor).", len(known))

    try:
        while True:
            time.sleep(5)
            current = _usb_devices(c)
            for dev in current - known:
                queue.put((ev.PHYSICAL, ev.USB_INSERTED, 0.6, f"Yeni Cihaz: {dev}"))
            for dev in known - current:
                queue.put((ev.PHYSICAL, ev.USB_REMOVED, 0.1, f"Cihaz Cikarildi: {dev}"))
            known = current
    except Exception as e:
        log.exception("Fiziksel sensor hatasi")
        queue.put((ev.PHYSICAL, ev.ERROR, 1.0, str(e)))
    finally:
        listener.stop()
        pythoncom.CoUninitialize()
