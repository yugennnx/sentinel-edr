import subprocess
import sys
import time

import psutil
import pytest

from sentinel.engine import response


@pytest.mark.parametrize("ip,beklenen", [
    ("127.0.0.1", False), ("127.5.5.5", False), ("::1", False), ("0.0.0.0", False),
    ("1.2.3.4 & calc", False), ("1.2.3.4; netsh", False), ("abc", False),
    ("10.40.154.50", True), ("8.8.8.8", True), ("2001:db8::1", True),
])
def test_ip_dogrulama(ip, beklenen):
    assert response.ip_engellenebilir_mi(ip)[0] is beklenen


def test_gecersiz_ip_komut_calistirmaz(monkeypatch):
    cagrildi = []
    monkeypatch.setattr(response.subprocess, "run", lambda *a, **k: cagrildi.append(a))
    assert response.dinamik_ip_engelle("1.2.3.4 & calc") is False
    assert cagrildi == []


def test_surec_sadece_ctime_eslesirse_oldurulur():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.3)
        ct = psutil.Process(p.pid).create_time()
        assert response.guvenli_surec_oldur(p.pid, ct + 5) is False
        assert p.poll() is None
        assert response.guvenli_surec_oldur(p.pid, ct) is True
        p.wait(5)
    finally:
        if p.poll() is None:
            p.kill()


def test_olmayan_surec():
    assert response.guvenli_surec_oldur(999999, 1.0) is False
