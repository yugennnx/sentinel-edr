"""YAML kural dosyasinin yuklenmesi ve dogrulanmasi.

Kurallar rules/sentinel_rules.yaml dosyasindadir (SENTINEL_RULES ile degistirilebilir).
Dosya bir kez yuklenir; hatali bir dosya RuleError ile, hatanin yeri belirtilerek reddedilir.
"""
import os
from dataclasses import dataclass, field

import yaml

from sentinel import events as ev
from sentinel.config import BASE_DIR

DEFAULT_RULES_PATH = os.path.join(BASE_DIR, "rules", "sentinel_rules.yaml")

PROCESS_RULE_KEYS = {"id", "name", "mitre", "process_names", "parent_names",
                     "cmdline_contains_any", "cmdline_tokens_any", "remote_port_not_in"}
EVENT_TYPES = {ev.KEYBOARD_ANOMALY, ev.USB_INSERTED, ev.USB_REMOVED, ev.SUSPICIOUS_PROCESS,
               ev.LOCAL_FILE_ACCESS, ev.DATA_EXFILTRATION, ev.NETWORK_SCAN}


class RuleError(ValueError):
    """Kural dosyasi gecersiz."""


def _lower_list(value, where):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"{where}: metin listesi olmali")
    return [v.lower() for v in value]


@dataclass(frozen=True)
class ProcessRule:
    id: str
    name: str
    mitre: str
    process_names: frozenset
    parent_names: frozenset = frozenset()
    cmdline_contains_any: tuple = ()
    cmdline_tokens_any: frozenset = frozenset()
    remote_port_not_in: frozenset | None = None

    def match(self, name, cmdline, parent_name, connections):
        """Kural eslesirse aciklama metnini, eslesmezse None dondurur."""
        if name.lower() not in self.process_names:
            return None
        detay = []

        if self.parent_names:
            if (parent_name or "").lower() not in self.parent_names:
                return None
            detay.append(f"{parent_name.lower()} -> {name.lower()}")

        if self.cmdline_contains_any or self.cmdline_tokens_any:
            cmd = " ".join(cmdline or []).lower()
            tokens = set(cmd.split())
            bulunan = next((k for k in self.cmdline_contains_any if k in cmd), None)
            bulunan = bulunan or next((k for k in self.cmdline_tokens_any if k in tokens), None)
            if bulunan is None:
                return None
            detay.append(bulunan)

        if self.remote_port_not_in is not None:
            hedef = next(((ip, port) for ip, port in connections
                          if port not in self.remote_port_not_in and not ip.startswith("127.") and ip != "::1"),
                         None)
            if hedef is None:
                return None
            detay.append(f"{hedef[0]}:{hedef[1]}")

        return f"[{self.id}] {self.name} ({', '.join(detay)})"


@dataclass(frozen=True)
class Rules:
    process_rules: tuple
    masquerade: dict
    data_staging: dict
    demo_signatures: dict
    weights: dict
    correlations: tuple
    multi_event_bonus: float
    sigmoid_slope: float
    sigmoid_center: float
    silent_kill_rules: frozenset = field(default_factory=frozenset)


def _parse_process_rule(raw, i):
    where = f"process_rules[{i}]"
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: sozluk olmali")
    bilinmeyen = set(raw) - PROCESS_RULE_KEYS
    if bilinmeyen:
        raise RuleError(f"{where} ({raw.get('id', '?')}): bilinmeyen alan(lar) {sorted(bilinmeyen)}")
    for zorunlu in ("id", "name", "process_names"):
        if zorunlu not in raw:
            raise RuleError(f"{where}: '{zorunlu}' alani zorunlu")
    where = f"{where} ({raw['id']})"
    if not any(k in raw for k in ("parent_names", "cmdline_contains_any", "cmdline_tokens_any", "remote_port_not_in")):
        raise RuleError(f"{where}: en az bir kosul (parent_names, cmdline_*, remote_port_not_in) gerekli")

    ports = None
    if "remote_port_not_in" in raw:
        ports = raw["remote_port_not_in"]
        if not isinstance(ports, list) or not all(isinstance(p, int) and 0 <= p <= 65535 for p in ports):
            raise RuleError(f"{where}.remote_port_not_in: port numarasi listesi olmali")
        ports = frozenset(ports)

    return ProcessRule(
        id=str(raw["id"]), name=str(raw["name"]), mitre=str(raw.get("mitre", "")),
        process_names=frozenset(_lower_list(raw["process_names"], f"{where}.process_names")),
        parent_names=frozenset(_lower_list(raw.get("parent_names", []), f"{where}.parent_names")),
        cmdline_contains_any=tuple(_lower_list(raw.get("cmdline_contains_any", []), f"{where}.cmdline_contains_any")),
        cmdline_tokens_any=frozenset(_lower_list(raw.get("cmdline_tokens_any", []), f"{where}.cmdline_tokens_any")),
        remote_port_not_in=ports,
    )


def parse_rules(data):
    """Ham YAML verisini dogrulayip Rules nesnesine cevirir."""
    if not isinstance(data, dict):
        raise RuleError("Kural dosyasi bir sozluk (YAML mapping) olmali")
    if data.get("version") != 1:
        raise RuleError(f"Desteklenmeyen kural dosyasi surumu: {data.get('version')!r} (beklenen: 1)")

    process_rules = tuple(_parse_process_rule(r, i) for i, r in enumerate(data.get("process_rules") or []))
    ids = [r.id for r in process_rules]
    if len(ids) != len(set(ids)):
        raise RuleError(f"Tekrarlanan kural kimligi: {sorted({i for i in ids if ids.count(i) > 1})}")

    masq = dict(data.get("masquerade") or {})
    masq["watched_binaries"] = frozenset(_lower_list(masq.get("watched_binaries", []), "masquerade.watched_binaries"))

    stg = dict(data.get("data_staging") or {})
    for k in ("archivers", "powershell_names", "powershell_keywords"):
        stg[k] = tuple(_lower_list(stg.get(k, []), f"data_staging.{k}"))

    demo = data.get("demo_signatures") or {}
    if not all(isinstance(k, str) and isinstance(v, str) and "{tag}" in v for k, v in demo.items()):
        raise RuleError("demo_signatures: her deger '{tag}' iceren bir metin olmali")

    risk = data.get("risk") or {}
    weights = risk.get("weights") or {}
    for olay, w in weights.items():
        if olay not in EVENT_TYPES:
            raise RuleError(f"risk.weights: bilinmeyen olay tipi {olay!r}")
        if not isinstance(w, (int, float)) or w < 0:
            raise RuleError(f"risk.weights.{olay}: negatif olmayan sayi olmali")

    correlations = []
    for i, c in enumerate(risk.get("correlations") or []):
        evs = c.get("events") if isinstance(c, dict) else None
        if not (isinstance(evs, list) and len(evs) == 2 and all(e in EVENT_TYPES for e in evs)):
            raise RuleError(f"risk.correlations[{i}].events: bilinen 2 olay tipi olmali")
        correlations.append((tuple(evs), float(c.get("bonus", 0))))

    silent = data.get("silent_kill_rules") or []
    bilinmeyen = set(silent) - set(ids)
    if bilinmeyen:
        raise RuleError(f"silent_kill_rules: tanimsiz kural kimligi {sorted(bilinmeyen)}")

    return Rules(
        process_rules=process_rules, masquerade=masq, data_staging=stg, demo_signatures=dict(demo),
        weights={k: float(v) for k, v in weights.items()}, correlations=tuple(correlations),
        multi_event_bonus=float(risk.get("multi_event_bonus", 0.0)),
        sigmoid_slope=float(risk.get("sigmoid_slope", 0.05)),
        sigmoid_center=float(risk.get("sigmoid_center", 50)),
        silent_kill_rules=frozenset(silent),
    )


def load_rules(path=None):
    path = path or os.environ.get("SENTINEL_RULES") or DEFAULT_RULES_PATH
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as e:
        raise RuleError(f"Kural dosyasi okunamadi: {path} ({e})") from e
    except yaml.YAMLError as e:
        raise RuleError(f"Kural dosyasi YAML hatasi: {path}\n{e}") from e
    try:
        return parse_rules(data)
    except RuleError as e:
        raise RuleError(f"{path}: {e}") from e


_aktif = None


def get_rules():
    """Aktif kurallari (ilk cagrida yukleyerek) dondurur."""
    global _aktif
    if _aktif is None:
        _aktif = load_rules()
    return _aktif
