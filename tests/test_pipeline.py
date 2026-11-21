"""Router + veritabani + karar motoru surecleri birlikte: kayip olmadan yazim ve temiz kapanis."""
import multiprocessing as mp
import sqlite3
import time

from sentinel.controller import _proc, message_router, shutdown
from sentinel.database import db_writer_worker
from sentinel.engine.fusion import ai_fusion_worker


def test_pipeline_kayipsiz_ve_temiz_kapanir(tmp_path):
    db = str(tmp_path / "t.db")
    sq, dq, aq = mp.Queue(), mp.Queue(), mp.Queue()
    router = _proc(message_router, sq, dq, aq, name="router")
    dbp = _proc(db_writer_worker, dq, db, name="db")
    ai = _proc(ai_fusion_worker, aq, name="ai")
    for p in (router, dbp, ai):
        p.start()
    time.sleep(1)

    # Kilit/engelleme tetiklemeyen olaylar (loopback IP engellenmez)
    sq.put(("NETWORK", "NETWORK_SCAN", 0.99, "Honeypot -> Kaynak IP: 127.0.0.1"))
    sq.put("bozuk-kayit")
    for i in range(50):
        sq.put(("CYBER", "TEST", 0.1, f"yuk {i}"))

    baslangic = time.time()
    shutdown([], router, dbp, ai, sq)
    assert time.time() - baslangic < 10
    assert [p.exitcode for p in (router, dbp, ai)] == [0, 0, 0]

    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 51
    conn.close()
