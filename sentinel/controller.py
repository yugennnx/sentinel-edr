import multiprocessing
import queue as queue_mod
import signal
import sys
import time

from sentinel.config import get_logger
from sentinel.database import db_writer_worker
from sentinel.engine.fusion import ai_fusion_worker
from sentinel.rules import RuleError, load_rules
from sentinel.sensors.exfil import exfil_worker
from sentinel.sensors.local import local_behavior_worker
from sentinel.sensors.network import network_layer_worker, scan_detector_worker
from sentinel.sensors.physical import physical_layer_worker
from sentinel.sensors.process import cyber_layer_worker

log = get_logger("controller")


def _run_worker(target, *args):
    """Alt surecler Ctrl+C'yi yok sayar; kapatmayi sadece ana surec yonetir.

    Windows'ta Ctrl+C konsoldaki TUM sureclere gider. Bu olmadan router ve
    veritabani sureci STOP mesajini almadan olur ve kapanis kilitlenirdi.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    target(*args)


def message_router(main_q, db_q, ai_q):
    while True:
        try:
            item = main_q.get(timeout=1)
        except queue_mod.Empty:
            continue
        except (EOFError, OSError):
            break
        if item == "STOP":
            # STOP once karar motoruna gider; motor son mudahale kayitlarini yazdiktan
            # sonra STOP'u veritabanina iletir. Boylece hicbir kayit kaybolmaz.
            ai_q.put("STOP")
            break
        db_q.put(item)
        ai_q.put(item)


def _proc(target, *args, name):
    return multiprocessing.Process(target=_run_worker, args=(target, *args), name=name, daemon=True)


def main():
    log.info("SENTINEL baslatiliyor...")

    # Kural dosyasi hataliysa hicbir sensor baslatilmadan durulur
    try:
        kurallar = load_rules()
    except RuleError as e:
        log.error("Kural dosyasi gecersiz, SENTINEL baslatilmadi: %s", e)
        sys.exit(2)
    log.info("%d surec kurali yuklendi.", len(kurallar.process_rules))

    sensor_queue = multiprocessing.Queue()
    db_queue = multiprocessing.Queue()
    ai_queue = multiprocessing.Queue()

    sensors = [
        _proc(physical_layer_worker, sensor_queue, name="sensor-physical"),
        _proc(cyber_layer_worker, sensor_queue, name="sensor-cyber"),
        _proc(network_layer_worker, sensor_queue, name="sensor-network"),
        _proc(scan_detector_worker, sensor_queue, name="sensor-scan"),
        _proc(exfil_worker, sensor_queue, name="sensor-exfil"),
        _proc(local_behavior_worker, sensor_queue, name="sensor-local"),
    ]
    db_process = _proc(db_writer_worker, db_queue, name="db-writer")
    ai_process = _proc(ai_fusion_worker, ai_queue, db_queue, name="ai-engine")
    router_process = _proc(message_router, sensor_queue, db_queue, ai_queue, name="router")

    # Tuketiciler once, ureticiler sonra baslar
    for p in [router_process, db_process, ai_process, *sensors]:
        p.start()

    log.info("Tum cekirdek moduller devrede (Fiziksel, Siber, Ag, Tarama, Sizdirma, Lokal, AI, Router).")
    log.info("Cikis yapmak icin konsolda Ctrl+C'ye basin.")

    try:
        while True:
            time.sleep(1)
            for p in [router_process, db_process, ai_process, *sensors]:
                if not p.is_alive() and p.exitcode not in (0, None):
                    log.error("Modul beklenmedik sekilde durdu: %s (cikis kodu %s)", p.name, p.exitcode)
                    sensors = [s for s in sensors if s is not p]
                    if p in (router_process, db_process, ai_process):
                        raise RuntimeError(f"Kritik modul coktu: {p.name}")
    except KeyboardInterrupt:
        log.info("Kapatilma sinyali alindi. Sistem guvenli moda geciyor...")
    except RuntimeError as e:
        log.error("%s - sistem kapatiliyor.", e)
    finally:
        shutdown(sensors, router_process, db_process, ai_process, sensor_queue)
        log.info("SENTINEL guvenle kapatildi.")
    sys.exit(0)


def shutdown(sensors, router_process, db_process, ai_process, sensor_queue):
    # 1) Yeni olay uretimini durdur
    for p in sensors:
        p.terminate()
    for p in sensors:
        p.join(timeout=3)

    # 2) Router hala canliyken STOP gonder; router bunu DB ve AI'ya iletir,
    #    boylece kuyrukta bekleyen loglar diske yazildiktan sonra kapanirlar.
    sensor_queue.put("STOP")
    for p in (router_process, db_process, ai_process):
        p.join(timeout=5)
        if p.is_alive():
            log.warning("%s zamaninda kapanmadi, zorla sonlandiriliyor.", p.name)
            p.terminate()
            p.join(timeout=2)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
