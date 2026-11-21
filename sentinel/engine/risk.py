"""Korelasyonlu risk skoru.

Pencere icindeki benzersiz olay tiplerinin agirliklari toplanir, birlikte gorulmesi
anlamli olan (korelasyonlu) olay ciftleri carpani artirir ve sonuc sigmoid ile
0-100 araligina sikistirilir. Tek basina zayif sinyaller esigi gecmez; birbirini
destekleyen sinyaller hizla kritik seviyeye cikar.

Agirliklar ve korelasyonlar rules/sentinel_rules.yaml dosyasindaki 'risk' bolumunden okunur.
"""
import math

from sentinel.rules import get_rules


def risk_skoru(olaylar, rules=None):
    """Benzersiz olay tiplerinden 0-100 arasi risk skoru hesaplar."""
    r = rules or get_rules()
    olaylar = set(olaylar)
    taban = sum(r.weights.get(o, 0.0) for o in olaylar)
    if taban == 0:
        return 0.0

    carpan = 1.0 + sum(bonus for (a, b), bonus in r.correlations if a in olaylar and b in olaylar)
    if len(olaylar) >= 3:
        carpan += r.multi_event_bonus

    ham = taban * carpan
    return round(100 / (1 + math.exp(-r.sigmoid_slope * (ham - r.sigmoid_center))), 2)
