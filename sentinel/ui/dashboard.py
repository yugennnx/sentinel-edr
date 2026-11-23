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

from sentinel.config import DB_PATH, EVENT_WINDOW_SECONDS, KILL_CHAIN_THRESHOLD  # noqa: E402
from sentinel.events import CRITICAL_EVENTS, CYBER, NETWORK, PHYSICAL, RESPONSE, SUSPICIOUS_PROCESS  # noqa: E402
from sentinel.ui import panel_veri as pv  # noqa: E402

AKTIF_IHLAL_SURESI = timedelta(seconds=60)   # Son kritik olaydan bu kadar sure sonra "guvende"
KURAL_REGEX = re.compile(r"\[(SNT-\d+)\]")

# Afisle ayni palet: fiziksel kehribar, siber kobalt, ag turkuaz, mudahale beyaz, kritik kirmizi
KRITIK, SUPHELI, NORMAL = "#ff5a5f", "#e8a33d", "#8db2ff"
KATMAN_RENK = {CYBER: "#8db2ff", PHYSICAL: "#e8a33d", NETWORK: "#2ec4b6", RESPONSE: "#ffffff"}
SERIT_SIRASI = [PHYSICAL, CYBER, NETWORK, RESPONSE]   # Zaman cizelgesinde alttan uste
IZLEME_SANIYE = 60
YAZI, SOLUK, CIZGI = "#e3f7ff", "#9fb4cc", "rgba(160,215,255,0.12)"
YAZI_TIPI = "Archivo, Bahnschrift, 'Segoe UI', sans-serif"

st.set_page_config(page_title="SENTINEL // Komuta Merkezi", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,100..800&display=swap');
    .stApp {
        color: #e3f7ff; font-family: Archivo, Bahnschrift, 'Segoe UI', sans-serif;
        background:
            radial-gradient(ellipse 70% 45% at 50% 0%, rgba(140,225,255,0.30), rgba(140,225,255,0) 70%),
            linear-gradient(180deg, #0b3d68 0%, #062746 38%, #03142a 100%);
        background-attachment: fixed;
    }
    header {visibility: hidden;}
    .block-container {padding-top: 1.6rem; padding-bottom: 1rem; max-width: 1500px;}

    .marka { display:flex; justify-content:space-between; align-items:flex-end; gap:24px;
             border-bottom:1px solid rgba(200,240,255,0.22); padding-bottom:14px; margin-bottom:22px; }
    .marka h1 { font-family: Archivo, Bahnschrift, sans-serif; font-variation-settings:"wdth" 125; font-weight:300;
                font-size:3.6rem; letter-spacing:0.22em; line-height:1; margin:0; padding:0; color:#fff;
                text-shadow:0 0 22px rgba(140,225,255,0.55); }
    .marka p { margin:8px 0 0 4px; font-size:1.05rem; letter-spacing:0.04em; color:#cfeaf8; font-weight:300; }
    .marka .alt { text-align:right; color:#9fb4cc; font-size:0.95rem; line-height:1.5; letter-spacing:0.03em; }
    .marka .alt b { color:#e3f7ff; font-weight:600; letter-spacing:0.08em; }

    .metrik { background:rgba(232,245,252,0.07); border:1px solid rgba(200,240,255,0.22); border-radius:10px;
              padding:16px 18px 14px; box-shadow:0 0 28px rgba(110,215,255,0.10), inset 0 1px 0 rgba(255,255,255,0.10); }
    .metrik h3 { color:#9fb4cc; font-size:0.9rem; font-weight:500; letter-spacing:0.06em; margin:0 0 6px 0; padding:0; }
    .metrik h1 { color:#fff; font-family: Archivo, Bahnschrift, sans-serif; font-variation-settings:"wdth" 115;
                 font-weight:300; font-size:2.7rem; line-height:1.05; margin:0; padding:0;
                 text-shadow:0 0 16px rgba(140,225,255,0.45); }
    .metrik.guvende { border-color:rgba(46,196,182,0.55); box-shadow:0 0 28px rgba(46,196,182,0.18); }
    .metrik.guvende h1 { color:#7ff0e4; text-shadow:0 0 16px rgba(46,196,182,0.55); }
    .metrik.alarm { border-color:rgba(255,90,95,0.75); background:rgba(255,90,95,0.10);
                    box-shadow:0 0 30px rgba(255,90,95,0.28); animation: nabiz 1.6s ease-in-out infinite; }
    .metrik.alarm h1 { color:#ff8a8d; text-shadow:0 0 18px rgba(255,90,95,0.6); }
    @keyframes nabiz { 50% { box-shadow:0 0 46px rgba(255,90,95,0.45); } }
    @media (prefers-reduced-motion: reduce) { .metrik.alarm { animation:none; } }

    .risk { background:rgba(232,245,252,0.07); border:1px solid rgba(200,240,255,0.22); border-radius:10px;
            padding:16px 20px 14px; height:100%; box-shadow:0 0 28px rgba(110,215,255,0.10); }
    .risk h3 { color:#9fb4cc; font-size:0.95rem; font-weight:500; letter-spacing:0.05em; margin:0; padding:0; }
    .risk .sayi { font-family: Archivo, Bahnschrift, sans-serif; font-variation-settings:"wdth" 120; font-weight:200;
                  font-size:5.2rem; line-height:1; color:#fff; margin:6px 0 10px; text-shadow:0 0 24px rgba(140,225,255,0.5); }
    .risk .sayi span { font-size:1.4rem; color:#9fb4cc; font-weight:300; margin-left:6px; text-shadow:none; }
    .olcek { position:relative; height:10px; border-radius:5px; background:rgba(200,240,255,0.12); }
    .olcek .dolu { position:absolute; left:0; top:0; bottom:0; border-radius:5px; background:#8db2ff;
                   box-shadow:0 0 12px rgba(141,178,255,0.7); }
    .olcek .esik { position:absolute; top:-5px; bottom:-5px; width:2px; background:#ff5a5f; }
    .olcek-etiket { display:flex; justify-content:space-between; font-size:0.8rem; color:#9fb4cc; margin-top:5px; }
    .risk p { margin:10px 0 8px; font-size:1rem; color:#e3f7ff; }
    .cip { display:inline-block; font-size:0.82rem; padding:2px 9px; margin:0 6px 6px 0; border-radius:20px;
           border:1px solid rgba(200,240,255,0.35); color:#e3f7ff; }
    .zirve { margin-top:6px; padding-top:8px; border-top:1px solid rgba(200,240,255,0.14); font-size:0.9rem; color:#9fb4cc; }
    .zirve b { color:#e3f7ff; font-weight:600; font-size:1.05rem; }
    .zirve.asildi b { color:#ff8a8d; }
    .risk.uyari .dolu { background:#e8a33d; box-shadow:0 0 12px rgba(232,163,61,0.7); }
    .risk.alarm { border-color:rgba(255,90,95,0.75); background:rgba(255,90,95,0.10); box-shadow:0 0 34px rgba(255,90,95,0.3); }
    .risk.alarm .sayi { color:#ff8a8d; text-shadow:0 0 24px rgba(255,90,95,0.6); }
    .risk.alarm .dolu { background:#ff5a5f; box-shadow:0 0 14px rgba(255,90,95,0.8); }

    h4.baslik, .baslik { font-family: Archivo, Bahnschrift, sans-serif; font-variation-settings:"wdth" 112; font-weight:300 !important;
              font-size:1.35rem; letter-spacing:0.08em; color:#e3f7ff; margin:26px 0 8px 0; padding:0 0 8px 0;
              border-bottom:1px solid rgba(200,240,255,0.18); }

    .akis { max-height:340px; overflow-y:auto; background:rgba(232,245,252,0.05);
            border:1px solid rgba(200,240,255,0.16); border-radius:10px; }
    table.loglar { width:100%; border-collapse:collapse; font-size:0.86rem; }
    table.loglar th { position:sticky; top:0; background:#0a2e50; color:#9fb4cc; font-weight:500; text-align:left;
                      letter-spacing:0.04em; border-bottom:1px solid rgba(200,240,255,0.25); padding:8px 10px; }
    table.loglar td { padding:6px 10px; border-bottom:1px solid rgba(200,240,255,0.07); vertical-align:top; color:#cfe3f2; }
    table.loglar td:first-child { white-space:nowrap; color:#9fb4cc; }
    tr.kritik td { color:#ffb3b5; background:rgba(255,90,95,0.10); }
    tr.kritik td:first-child { box-shadow: inset 3px 0 0 #ff5a5f; }
    tr.supheli td { color:#f5cf8f; background:rgba(232,163,61,0.07); }
    tr.supheli td:first-child { box-shadow: inset 3px 0 0 #e8a33d; }
    tr.mudahale td { color:#ffffff; background:rgba(140,225,255,0.12); font-weight:600; }
    tr.mudahale td:first-child { box-shadow: inset 3px 0 0 #ffffff; }
    .tag { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:7px; vertical-align:1px; }
    .kural { border:1px solid currentColor; border-radius:4px; padding:0 5px; font-size:0.76rem; letter-spacing:0.03em; }

    .bant { margin-top:26px; padding:12px 18px; border-radius:10px; background:rgba(232,245,252,0.92); color:#0b2740;
            display:flex; flex-wrap:wrap; gap:6px 0; align-items:center; font-weight:600; font-size:0.95rem; }
    .bant span { padding:0 14px; border-left:3px solid #0b2740; line-height:1.1; }
    .bant span:first-child { border-left:0; padding-left:0; color:#2a6f9e; font-weight:500; letter-spacing:0.04em; }
    div[data-testid="stAlert"] { background:rgba(232,245,252,0.07); border:1px solid rgba(200,240,255,0.22); color:#e3f7ff; }
</style>
""", unsafe_allow_html=True)
st.markdown("""
<div class="marka">
  <div><h1>SENTINEL</h1><p>Sen fark etmeden, o çoktan fark etti.</p></div>
  <div class="alt"><b>KOMUTA MERKEZİ</b><br>Siber-fiziksel EDR/IPS · canlı izleme</div>
</div>
""", unsafe_allow_html=True)


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


def risk_kutusu(risk, tipler, zirve):
    """Son korelasyon penceresindeki olaylardan hesaplanan anlik risk gostergesi (HTML)."""
    if risk >= KILL_CHAIN_THRESHOLD:
        durum, mesaj = "alarm", "Eşik aşıldı: karar motoru müdahale eder."
    elif tipler:
        durum, mesaj = "uyari", "İzleniyor: sinyaller tek başına eşiğin altında."
    else:
        durum, mesaj = "", "Pencere sakin. Son saniyelerde tespit yok."
    cipler = "".join(f'<span class="cip">{html.escape(pv.olay_adi(t))}</span>' for t in tipler)
    esik = KILL_CHAIN_THRESHOLD
    return (f'<div class="risk {durum}"><h3>Anlık risk, son {EVENT_WINDOW_SECONDS} saniye</h3>'
            f'<div class="sayi">{risk:.0f}<span>/ 100</span></div>'
            f'<div class="olcek"><div class="dolu" style="width:{min(risk, 100):.1f}%"></div>'
            f'<div class="esik" style="left:{esik:.0f}%"></div></div>'
            f'<div class="olcek-etiket"><span>0</span><span style="color:#ff8a8d">müdahale eşiği {esik:.0f}</span>'
            f'<span>100</span></div><p>{mesaj}</p>{cipler}'
            f'<div class="zirve{" asildi" if zirve >= esik else ""}">Son {IZLEME_SANIYE} saniyenin zirvesi: '
            f'<b>{zirve:.0f}</b></div></div>')


def pencere_grafigi(kayitlar, simdi):
    """Son IZLEME_SANIYE saniyeyi katman seritlerinde gosterir; son korelasyon penceresi vurgulanir."""
    seritler = [pv.katman_adi(k) for k in SERIT_SIRASI]
    fig = go.Figure()
    # Tum seritlerin her zaman gorunmesi icin gorunmez bir iz
    fig.add_trace(go.Scatter(x=[-999] * len(seritler), y=seritler, mode="markers", marker=dict(opacity=0),
                             showlegend=False, hoverinfo="skip"))
    son = pv.son_kayitlar(kayitlar, simdi, IZLEME_SANIYE)
    for katman in SERIT_SIRASI:
        secili = [(s, k) for s, k in son if k["layer"] == katman]
        if not secili:
            continue
        fig.add_trace(go.Scatter(
            x=[-s for s, _ in secili], y=[pv.katman_adi(katman)] * len(secili), mode="markers",
            name=pv.katman_adi(katman), showlegend=False,
            marker=dict(color=KATMAN_RENK[katman], size=16, symbol="diamond", line=dict(color="#03142a", width=2)),
            text=[f"{pv.olay_adi(k['event_type'])}<br>{html.escape(str(k['message']))[:110]}" for _, k in secili],
            hovertemplate="%{text}<extra>%{x:.0f} sn</extra>"))
    fig.add_vrect(x0=-EVENT_WINDOW_SECONDS, x1=0.8, fillcolor="rgba(140,225,255,0.13)", line_width=0, layer="below")
    fig.add_annotation(x=-EVENT_WINDOW_SECONDS / 2, y=1.08, yref="paper", showarrow=False,
                       text="korelasyon penceresi", font=dict(color=YAZI, size=12))
    if not son:
        fig.add_annotation(x=-IZLEME_SANIYE / 2, y=0.5, yref="paper", showarrow=False,
                           text=f"Son {IZLEME_SANIYE} saniyede olay yok", font=dict(color=SOLUK, size=14))
    _grafik_duzeni(fig, yukseklik=262)
    fig.update_xaxes(range=[-IZLEME_SANIYE, 1], tickvals=list(range(-IZLEME_SANIYE, 1, 10)),
                     ticktext=[f"{v} sn" if v else "şimdi" for v in range(-IZLEME_SANIYE, 1, 10)])
    fig.update_yaxes(categoryorder="array", categoryarray=seritler, range=[-0.6, len(seritler) - 0.4],
                     tickfont=dict(color=YAZI, size=13))
    fig.update_layout(margin=dict(t=34, b=24, l=10, r=10))
    return fig


def _grafik_duzeni(fig, yukseklik=300):
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color=SOLUK, family=YAZI_TIPI, size=13), margin=dict(t=20, b=20, l=20, r=20),
                      height=yukseklik, legend=dict(font=dict(color=YAZI), orientation="h", y=1.12, x=0),
                      hoverlabel=dict(bgcolor="#0a2e50", bordercolor="rgba(200,240,255,0.4)",
                                      font=dict(color=YAZI, family=YAZI_TIPI)))
    fig.update_xaxes(showgrid=True, gridcolor=CIZGI, zeroline=False, linecolor=CIZGI)
    fig.update_yaxes(showgrid=True, gridcolor=CIZGI, zeroline=False, linecolor=CIZGI)
    return fig


def metrik(kolon, baslik, deger, durum=""):
    """durum: '' (normal), 'alarm' (kirmizi, nabiz) veya 'guvende' (turkuaz)."""
    kolon.markdown(f'<div class="metrik {durum}"><h3>{baslik}</h3><h1>{deger}</h1></div>', unsafe_allow_html=True)


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
        nokta = f'<span class="tag" style="background:{KATMAN_RENK.get(k["layer"], SOLUK)}"></span>'
        satirlar.append(f'<tr class="{sinif}"><td>{html.escape(str(k["timestamp"]))}</td>'
                        f'<td>{nokta}{html.escape(pv.katman_adi(k["layer"]))}</td>'
                        f'<td>{html.escape(pv.olay_adi(k["event_type"]))}</td>'
                        f'<td>{float(k["confidence"]):.2f}</td><td>{mesaj}</td></tr>')
    return ('<div class="akis"><table class="loglar"><tr><th>Zaman</th><th>Katman</th>'
            '<th>Olay</th><th>Güven</th><th>Detay</th></tr>' + "".join(satirlar) + "</table></div>")


@st.fragment(run_every="2s")
def canli_komuta_merkezi():
    kayitlar = fetch_data()
    if not kayitlar:
        st.info("Henüz kayıt yok. Sensörler çalışıyor; ilk olay geldiğinde panel kendiliğinden dolacak.")
        return

    simdi = datetime.now()
    mudahaleler = [k for k in kayitlar if k["layer"] == RESPONSE]
    tespitler = [k for k in kayitlar if k["layer"] != RESPONSE]
    kritikler = [k for k in tespitler if k["event_type"] in CRITICAL_EVENTS]
    son_kritik = next((pv.zaman(k["timestamp"]) for k in kritikler), None)
    aktif_ihlal = son_kritik is not None and simdi - son_kritik <= AKTIF_IHLAL_SURESI
    kurallar = Counter(m for k in kayitlar for m in KURAL_REGEX.findall(str(k["message"])))
    risk, tipler = pv.pencere_riski(kayitlar, simdi)
    zirve = pv.risk_zirvesi(kayitlar, simdi, IZLEME_SANIYE)

    r1, r2 = st.columns([1, 2.4])
    r1.markdown(risk_kutusu(risk, tipler, zirve), unsafe_allow_html=True)
    with r2:
        st.plotly_chart(pencere_grafigi(kayitlar, simdi), width="stretch", key="pencere",
                        config={"displayModeBar": False})

    c1, c2, c3, c4, c5 = st.columns([1, 1, 1.6, 1, 1])
    metrik(c1, "Tespit", len(tespitler))
    metrik(c2, "Kritik olay", len(kritikler), "alarm" if kritikler else "")
    metrik(c3, "Sistem durumu", "AKTİF İHLAL" if aktif_ihlal else "GÜVENDE", "alarm" if aktif_ihlal else "guvende")
    metrik(c4, "Müdahale", sum(1 for k in mudahaleler if not str(k["message"]).startswith("KARAR")))
    metrik(c5, "Tetiklenen kural", len(kurallar))

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("<h4 class='baslik'>Tehdit dağılımı</h4>", unsafe_allow_html=True)
        sayim = Counter(k["event_type"] for k in tespitler)
        etiketler = list(sayim)
        fig = go.Figure(go.Bar(
            x=[sayim[e] for e in etiketler], y=[pv.olay_adi(e) for e in etiketler], orientation="h",
            marker=dict(color=[KRITIK if e in CRITICAL_EVENTS else SUPHELI if e == SUSPICIOUS_PROCESS else NORMAL
                               for e in etiketler], line=dict(width=0)),
            hovertemplate="%{y}: %{x} olay<extra></extra>"))
        st.plotly_chart(_grafik_duzeni(fig), width="stretch", key="dagilim",
                        config={"displayModeBar": False})

    with g2:
        st.markdown("<h4 class='baslik'>Olay geçmişi</h4>", unsafe_allow_html=True)
        fig = go.Figure()
        for katman, renk in KATMAN_RENK.items():
            secili = [k for k in reversed(kayitlar[:60]) if k["layer"] == katman]
            if secili:
                fig.add_trace(go.Scatter(x=[k["timestamp"] for k in secili],
                                         y=[pv.olay_adi(k["event_type"]) for k in secili],
                                         mode="markers", name=pv.katman_adi(katman),
                                         marker=dict(color=renk, size=11, line=dict(color="#03142a", width=2)),
                                         text=[k["message"] for k in secili], hoverinfo="text+x"))
        st.plotly_chart(_grafik_duzeni(fig), width="stretch", key="zaman",
                        config={"displayModeBar": False})

    st.markdown("<h4 class='baslik'>Canlı olay akışı</h4>", unsafe_allow_html=True)
    st.markdown(log_tablosu(kayitlar[:100]), unsafe_allow_html=True)


canli_komuta_merkezi()

st.markdown('<div class="bant"><span>Algılar, ilişkilendirir, müdahale eder</span><span>USB ve BadUSB</span>'
            '<span>Süreç ve maskeleme</span><span>Veri sızdırma</span><span>Port tarama ve tuzak port</span>'
            '<span>Otonom müdahale</span></div>', unsafe_allow_html=True)
