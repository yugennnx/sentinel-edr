import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import plotly.graph_objects as go

from config import DB_PATH

# ==========================================
# 1. SABİT İSKELET VE CSS (ASLA YENİLENMEZ)
# ==========================================
st.set_page_config(page_title="SENTINEL // NEURAL CORE", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #070707; color: #4AF626; font-family: 'Consolas', monospace; }
    .stDataFrame { border: 1px solid #1f5e1f !important; background-color: #0a0e0a !important;}
    .metrik-kutu { background-color: #0a0e0a; border: 1px solid #1f5e1f; padding: 20px; border-radius: 5px; text-align: center; box-shadow: inset 0 0 15px rgba(74, 246, 38, 0.05); }
    .metrik-kutu h3 { color: #8FBC8F; font-size: 1rem; margin-bottom: 10px; text-transform: uppercase; font-weight: bold; }
    .metrik-kutu h1 { color: #4AF626; font-size: 3rem; margin: 0; text-shadow: 0 0 10px rgba(74, 246, 38, 0.3); }
    .kirmizi-alarm { border-color: #FF003C; box-shadow: inset 0 0 25px rgba(255, 0, 60, 0.2); }
    .kirmizi-alarm h3, .kirmizi-alarm h1 { color: #FF003C; text-shadow: 0 0 10px rgba(255, 0, 60, 0.5); }
    
    header {visibility: hidden;}
    .block-container {padding-top: 1rem; padding-bottom: 0rem;}
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align: center; color: #4AF626; text-shadow: 0 0 15px #228B22; border-bottom: 1px solid rgba(74,246,38,0.3); padding-bottom: 10px; font-family: Courier New;'>🛡️ SENTINEL SİBER-FİZİKSEL KOMUTA MERKEZİ</h1>", unsafe_allow_html=True)

DB_NAME = DB_PATH

# Kirmizi alarm uretecek olay tipleri (tum yuksek riskli olaylar)
KRITIK_OLAYLAR = ["USB_INSERTED", "DATA_EXFILTRATION", "KEYBOARD_ANOMALY", "LOCAL_FILE_ACCESS", "NETWORK_SCAN"]

def fetch_data():
    try:
        conn = sqlite3.connect(f"file:{DB_NAME}?mode=ro", uri=True, timeout=1)
        try:
            return pd.read_sql_query("SELECT timestamp, layer, event_type, confidence, message FROM logs ORDER BY id DESC LIMIT 100", conn)
        finally:
            conn.close()
    except (sqlite3.Error, pd.errors.DatabaseError):
        return pd.DataFrame()

# ==========================================
# 2. FRAGMENT MİMARİSİ (SADECE BURASI GÜNCELLENİR)
# ==========================================
# Bu dekoratör, tüm sayfanın kaymasını engeller. Sadece bu bloğun içini 2 saniyede bir günceller.
@st.fragment(run_every="2s")
def canli_komuta_merkezi():
    df = fetch_data()
    
    if not df.empty:
        cyber_count = len(df[df['layer'] == 'CYBER'])
        phys_count = len(df[df['layer'] == 'PHYSICAL'])
        
        # Son olaya göre anlık risk tespiti (Füzyon Kararı)
        son_olay = df.iloc[0]['event_type']
        kilit_tehdit = son_olay in KRITIK_OLAYLAR
        
        durum_sinif = "metrik-kutu kirmizi-alarm" if kilit_tehdit else "metrik-kutu"
        durum_yazi = "AKTİF İHLAL TESPİTİ" if kilit_tehdit else "SİSTEM GÜVENDE"

        # --- DİNAMİK METRİKLER ---
        c1, c2, c3 = st.columns([1, 1.5, 1])
        c1.markdown(f'<div class="metrik-kutu"><h3>Siber Katman (Olay)</h3><h1>{cyber_count}</h1></div>', unsafe_allow_html=True)
        c2.markdown(f'<div class="{durum_sinif}"><h3>Sistem Statüsü</h3><h1 style="font-size:2.2rem; padding-top:10px;">{durum_yazi}</h1></div>', unsafe_allow_html=True)
        c3.markdown(f'<div class="metrik-kutu"><h3>Fiziksel Katman (Olay)</h3><h1>{phys_count}</h1></div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        # --- İSTİHBARAT GRAFİKLERİ ---
        g1, g2 = st.columns(2)
        with g1:
            st.markdown("<h4 style='color:#8FBC8F; font-family: Consolas;'>[!] Tehdit Dağılımı (Radar)</h4>", unsafe_allow_html=True)
            olay_sayilari = df['event_type'].value_counts()
            fig_radar = go.Figure(go.Scatterpolar(
                r=olay_sayilari.values,
                theta=olay_sayilari.index,
                fill='toself',
                line_color='#4AF626',
                fillcolor='rgba(74, 246, 38, 0.3)'
            ))
            fig_radar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", polar=dict(radialaxis=dict(visible=False), angularaxis=dict(tickfont=dict(color="#8FBC8F", size=11))), margin=dict(t=20, b=20, l=20, r=20), height=300)
            st.plotly_chart(fig_radar, use_container_width=True, key="radar_chart")
            
        with g2:
            st.markdown("<h4 style='color:#8FBC8F; font-family: Consolas;'>[~] Risk Skoru Eğilimi</h4>", unsafe_allow_html=True)
            fig_line = px.line(df.head(30)[::-1], x='timestamp', y='confidence', color='layer', markers=True, color_discrete_map={"CYBER": "#FFD700", "PHYSICAL": "#FF003C", "NETWORK": "#00FFFF"})
            fig_line.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", xaxis=dict(showgrid=True, gridcolor='rgba(74,246,38,0.1)', title='', tickfont=dict(color="#8FBC8F")), yaxis=dict(showgrid=True, gridcolor='rgba(74,246,38,0.1)', title='', tickfont=dict(color="#8FBC8F")), legend=dict(font=dict(color="#8FBC8F")), margin=dict(t=20, b=20, l=20, r=20), height=300)
            st.plotly_chart(fig_line, use_container_width=True, key="line_chart")

        # --- HAM VERİ AKIŞI (SİNİR AĞI) ---
        st.markdown("<h4 style='color:#8FBC8F; border-bottom: 1px solid #1f5e1f; font-family: Consolas;'>[>] SİNİR AĞI VERİ AKIŞI</h4>", unsafe_allow_html=True)
        def satir_renklendir(row):
            if row['event_type'] in KRITIK_OLAYLAR:
                return ['background-color: rgba(255, 0, 60, 0.15); color: #FF003C'] * len(row)
            if row['event_type'] == 'SUSPICIOUS_PROCESS':
                return ['background-color: rgba(255, 215, 0, 0.1); color: #FFD700'] * len(row)
            return ['color: #4AF626'] * len(row)
        
        st.dataframe(df.style.apply(satir_renklendir, axis=1), use_container_width=True, height=250)

    else:
        st.info("[*] Sistem Temiz. Sensörlerden Veri Akışı Bekleniyor...")

# Motoru Ateşle
canli_komuta_merkezi()