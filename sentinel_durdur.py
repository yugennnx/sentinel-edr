"""Bu klasorden baslatilmis SENTINEL sureclerini (ve alt sureclerini) kapatir.

Sistemdeki diger Python programlarina dokunmaz.
"""
import os

import psutil

BASE_DIR = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))
BETIKLER = {"controller.py", "baslat.py", "arayuz.py", "dashboard.py", "nemesis.py"}


def sentinel_sureci_mi(proc):
    try:
        cmdline = proc.cmdline()
        if not proc.name().lower().startswith("python"):
            return False
        cwd = os.path.normcase(proc.cwd())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    for arg in cmdline[1:]:
        tam_yol = os.path.normcase(os.path.abspath(os.path.join(cwd, arg)))
        if os.path.basename(tam_yol) in BETIKLER and os.path.dirname(tam_yol) == BASE_DIR:
            return True
    return False


def main():
    benim_pid = os.getpid()
    hedefler = {}
    for proc in psutil.process_iter():
        if proc.pid != benim_pid and sentinel_sureci_mi(proc):
            hedefler[proc.pid] = proc
            try:
                for alt in proc.children(recursive=True):
                    hedefler[alt.pid] = alt
            except psutil.NoSuchProcess:
                pass

    for p in hedefler.values():
        try:
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(list(hedefler.values()), timeout=3)
    print(f"[+] {len(hedefler)} SENTINEL sureci kapatildi.")


if __name__ == "__main__":
    main()
