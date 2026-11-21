"""SENTINEL web paneli (Streamlit).

Calistirma: python run.py --ui dashboard
pandas gerektirmez: veriler dogrudan sqlite3 ile okunur, tablo HTML olarak cizilir.
"""
import html
import os
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timedelta

# Betik dogrudan calistirildiginda (streamlit run) proje kokunu import yoluna ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from sentinel.config import DB_PATH  # noqa: E402
from sentinel.events import CRITICAL_EVENTS, RESPONSE, SUSPICIOUS_PROCESS  # noqa: E402

AKTIF_IHLAL_SURESI = timedelta(seconds=60)   # Son kritik olaydan bu kadar sure sonra "guvende"
KURAL_REGEX = re.compile(r"\[(SNT-\d+)\]")
KATMAN_RENK = {"CYBER": "#FFD700", "PHYSICAL": "#FF003C", "NETWORK": "#00FFFF", RESPONSE: "#FFFFFF"}

st.set_page_config(page_title="SENTINEL // Komuta Merkezi", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
    .stApp { background-color: #070707; color: #4AF626; font-family: 'Consolas', monospace; }
    header {visibility: hidden;}
    .block-container {padding-top: 1rem; padding-bottom: 0rem;}
    .metrik { background:#0a0e0a; border:1px solid #1f5e1f; padding:16px; border-radius:6px; text-align:center;
              box-shadow: inset 0 0 15px rgba(74,246,38,0.05); }
    .metrik h3 { color:#8FBC8F; font-size:0.85rem; margin:0 0 6px 0; text-transform:uppercase; }
    .metrik h1 { color:#4AF626; font-size:2.4rem; margin:0; text-shadow:0 0 10px rgba(74,246,38,0.3); }
    .alarm { border-color:#FF003C; box-shadow: inset 0 0 25px rgba(255,0,60,0.2); }
    .alarm h3, .alarm h1 { color:#FF003C; text-shadow:0 0 10px rgba(255,0,60,0.5); }
    .baslik { color:#8FBC8F; font-family:Consolas; margin:18px 0 6px 0; border-bottom:1px solid #1f5e1f; }
    table.loglar { width:100%; border-collapse:collapse; font-size:0.8rem; }
    table.loglar th { color:#8FBC8F; text-align:left; border-bottom:1px solid #1f5e1f; padding:4px 6px; }
    table.loglar td { padding:4px 6px; border-bottom:1px solid #102510; vertical-align:top; }
    tr.kritik td { color:#FF003C; background:rgba(255,0,60,0.10); }
    tr.supheli td { color:#FFD700; background:rgba(255,215,0,0.06); }
    tr.normal td { color:#4AF626; }
    tr.mudahale td { color:#E8F7FF; background:rgba(0,190,255,0.12); font-weight:bold; }
    table.loglar td:first-child { white-space:nowrap; }
    .kural { border:1px solid currentColor; border-radius:3px; padding:0 4px; font-size:0.72rem; }
</style>
""", unsafe_allow_html=True)
st.markdown("<h1 style='text-align:center; color:#4AF626; text-shadow:0 0 15px #228B22; "
            "border-bottom:1px solid rgba(74,246,38,0.3); padding-bottom:10px; font-family:Courier New;'>"
            "🛡️ SENTINEL SİBER-FİZİKSEL KOMUTA MERKEZİ</h1>", unsafe_allow_html=True)


def fetch_data(limit=200):
    """Son kayitlari (en yeni ilk) sozluk listesi olarak dondurur."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=1)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT timestamp, layer, event_type, confidence, message FROM logs "
                                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def _zaman(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _grafik_duzeni(fig, yukseklik=300):
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#8FBC8F", family="Consolas"), margin=dict(t=20, b=20, l=20, r=20),
                      height=yukseklik, legend=dict(font=dict(color="#8FBC8F")))
    return fig


def metrik(kolon, baslik, deger, alarm=False):
    kolon.markdown(f'<div class="metrik{" alarm" if alarm else ""}"><h3>{baslik}</h3><h1>{deger}</h1></div>',
                   unsafe_allow_html=True)


def log_tablosu(kayitlar):
    satirlar = []
    for k in kayitlar:
        if k["layer"] == RESPONSE:
            sinif = "mudahale"
        elif k["event_type"] in CRITICAL_EVENTS:
            sinif = "kritik"
        else:
            sinif = "supheli" if k["event_type"] == SUSPICIOUS_PROCESS else "normal"
        mesaj = html.escape(str(k["message"]))  # Surec adlari / komut satirlari HTML olarak yorumlanmasin
        mesaj = KURAL_REGEX.sub(r'<span class="kural">\1</span>', mesaj)
        satirlar.append(f'<tr class="{sinif}"><td>{html.escape(str(k["timestamp"]))}</td>'
                        f'<td>{html.escape(str(k["layer"]))}</td><td>{html.escape(str(k["event_type"]))}</td>'
                        f'<td>{float(k["confidence"]):.2f}</td><td>{mesaj}</td></tr>')
    return ('<div style="max-height:320px; overflow-y:auto;"><table class="loglar"><tr><th>Zaman</th><th>Katman</th>'
            '<th>Olay</th><th>Güven</th><th>Detay</th></tr>' + "".join(satirlar) + "</table></div>")


@st.fragment(run_every="2s")
def canli_komuta_merkezi():
    kayitlar = fetch_data()
    if not kayitlar:
        st.info("[*] Sistem temiz. Sensörlerden veri akışı bekleniyor...")
        return

    simdi = datetime.now()
    mudahaleler = [k for k in kayitlar if k["layer"] == RESPONSE]
    tespitler = [k for k in kayitlar if k["layer"] != RESPONSE]
    kritikler = [k for k in tespitler if k["event_type"] in CRITICAL_EVENTS]
    son_kritik = next((_zaman(k["timestamp"]) for k in kritikler), None)
    aktif_ihlal = son_kritik is not None and simdi - son_kritik <= AKTIF_IHLAL_SURESI
    kurallar = Counter(m for k in kayitlar for m in KURAL_REGEX.findall(str(k["message"])))

    c1, c2, c3, c4, c5 = st.columns([1, 1, 1.6, 1, 1])
    metrik(c1, "Tespit", len(tespitler))
    metrik(c2, "Kritik Olay", len(kritikler), alarm=bool(kritikler))
    metrik(c3, "Sistem Statüsü", "AKTİF İHLAL" if aktif_ihlal else "GÜVENDE", alarm=aktif_ihlal)
    metrik(c4, "Müdahale", sum(1 for k in mudahaleler if not str(k["message"]).startswith("KARAR")))
    metrik(c5, "Tetiklenen Kural", len(kurallar))

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("<h4 class='baslik'>[!] Tehdit Dağılımı</h4>", unsafe_allow_html=True)
        sayim = Counter(k["event_type"] for k in tespitler)
        etiketler = list(sayim)
        fig = go.Figure(go.Bar(
            x=[sayim[e] for e in etiketler], y=etiketler, orientation="h",
            marker_color=["#FF003C" if e in CRITICAL_EVENTS else "#FFD700" if e == SUSPICIOUS_PROCESS else "#4AF626"
                          for e in etiketler]))
        fig.update_xaxes(showgrid=True, gridcolor="rgba(74,246,38,0.1)")
        st.plotly_chart(_grafik_duzeni(fig), width="stretch", key="dagilim")

    with g2:
        st.markdown("<h4 class='baslik'>[~] Olay Zaman Çizelgesi</h4>", unsafe_allow_html=True)
        fig = go.Figure()
        for katman, renk in KATMAN_RENK.items():
            secili = [k for k in reversed(kayitlar[:60]) if k["layer"] == katman]
            if secili:
                fig.add_trace(go.Scatter(x=[k["timestamp"] for k in secili],
                                         y=["MÜDAHALE" if katman == RESPONSE else k["event_type"] for k in secili],
                                         mode="markers", name=katman, marker=dict(color=renk, size=11),
                                         text=[k["message"] for k in secili], hoverinfo="text+x"))
        fig.update_xaxes(showgrid=True, gridcolor="rgba(74,246,38,0.1)")
        fig.update_yaxes(showgrid=True, gridcolor="rgba(74,246,38,0.1)")
        st.plotly_chart(_grafik_duzeni(fig), width="stretch", key="zaman")

    st.markdown("<h4 class='baslik'>[>] Canlı Olay Akışı</h4>", unsafe_allow_html=True)
    st.markdown(log_tablosu(kayitlar[:100]), unsafe_allow_html=True)


canli_komuta_merkezi()
