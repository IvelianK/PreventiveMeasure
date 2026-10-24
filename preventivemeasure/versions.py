"""Comparación genérica de versiones y evaluación de rangos CPE.

Los ecosistemas con OSV se comparan en el servidor de OSV; esto solo se usa
para rangos de NVD (CPE) y para elegir la versión corregida más cercana.
"""
import functools
import re

_TOKEN = re.compile(r"\d+|[a-z]+")
_PRE = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "preview": 3, "rc": 4, "c": 4}


def _tokens(v: str) -> list:
    v = v.strip().lower()
    v = v.split(":", 1)[1] if re.match(r"^\d+:", v) else v  # epoch dpkg/rpm
    v = v.lstrip("v").split("+", 1)[0]
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(v)]


def _tail(rest: list) -> int:
    """Signo de la cola sobrante de la versión más larga frente a 'nada'."""
    for t in rest:
        if t == 0:
            continue
        return -1 if isinstance(t, str) and t in _PRE else 1
    return 0


def _cmp_tok(a, b) -> int:
    match (isinstance(a, int), isinstance(b, int)):
        case (True, True):
            return (a > b) - (a < b)
        case (True, False):
            return 1  # 1.0.1 > 1.0.rc / 1.0.k
        case (False, True):
            return -1
    pa, pb = a in _PRE, b in _PRE
    if pa and pb:
        return (_PRE[a] > _PRE[b]) - (_PRE[a] < _PRE[b])
    if pa != pb:
        return -1 if pa else 1
    return (a > b) - (a < b)


def compare(a: str, b: str) -> int:
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if c := _cmp_tok(x, y):
            return c
    if len(ta) > len(tb):
        return _tail(ta[len(tb):])
    if len(tb) > len(ta):
        return -_tail(tb[len(ta):])
    return 0


sort_key = functools.cmp_to_key(compare)


def in_range(version: str, exact: str | None = None, start_inc: str | None = None,
             start_exc: str | None = None, end_inc: str | None = None, end_exc: str | None = None) -> bool:
    """Semántica de cpeMatch de NVD. exact '*'/'-'/None = sin versión fija."""
    if not version:
        return False
    if exact not in (None, "", "*", "-"):
        return compare(version, exact) == 0
    if start_inc and compare(version, start_inc) < 0:
        return False
    if start_exc and compare(version, start_exc) <= 0:
        return False
    if end_inc and compare(version, end_inc) > 0:
        return False
    if end_exc and compare(version, end_exc) >= 0:
        return False
    # cpe con '*' y sin rangos = todas las versiones; NVD lo usa poco y es ruidoso
    return any((start_inc, start_exc, end_inc, end_exc))


_CPE_SPLIT = re.compile(r"(?<!\\):")


def parse_cpe(cpe: str) -> dict:
    p = _CPE_SPLIT.split(cpe)
    p += ["*"] * (13 - len(p))
    unesc = lambda s: s.replace("\\", "")
    return {"part": p[2], "vendor": unesc(p[3]), "product": unesc(p[4]), "version": unesc(p[5])}
