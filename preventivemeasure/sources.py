"""Fuentes de inteligencia: OSV, NVD, CISA KEV, FIRST EPSS y feeds RSS de ciberseguridad."""
import datetime as dt
import html
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import cvss
from .manifests import norm_product, safe_xml
from .versions import compare, parse_cpe, sort_key

UA = "PreventiveMeasure/1.0"
OSV = "https://api.osv.dev/v1"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"

# Metadatos cloud y enlace local: bloqueados siempre, incluso para webs de intranet
ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in
                  ("169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32", "0.0.0.0/8")]


def check_url(url: str, allow_private: bool = True) -> None:
    """Freno de SSRF: solo http(s) y nunca hacia metadatos cloud; opcionalmente solo IPs públicas."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError(f"URL no permitida: {p.scheme}://{p.hostname or ''}")
    host = p.hostname.rstrip(".")
    if host.lower() == "metadata.google.internal":
        raise ValueError("Destino de metadatos bloqueado")

    def reject_ip(address: str) -> None:
        ip = ipaddress.ip_address(address.split("%")[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if any(ip in n for n in ALWAYS_BLOCKED) or (not allow_private and not ip.is_global):
            raise ValueError(f"Destino bloqueado: {host} -> {ip}")

    try:
        literal = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        pass
    else:
        reject_ip(str(literal))  # también con HTTP(S)_PROXY: el proxy podría acceder a esa IP
    if urllib.request.getproxies().get(p.scheme):
        return  # el proxy resuelve el DNS: validar aquí bloquearía todo en redes corporativas
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return  # urlopen dará el error de red real
    for *_, sa in infos:
        reject_ip(sa[0])
    # ponytail: TOCTOU por DNS rebinding entre comprobar y conectar; fijar la IP en la conexión si el modelo lo exige


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_private: bool):
        super().__init__()
        self.allow_private = allow_private

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.allow_private)  # cada salto, no solo la URL inicial
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(req: urllib.request.Request, timeout: int, allow_private: bool = True):
    check_url(req.full_url, allow_private)
    return urllib.request.build_opener(_CheckedRedirect(allow_private)).open(req, timeout=timeout)


def read_capped(r, max_bytes: int, timeout: int) -> bytes:
    """El timeout de urllib es por operación de socket: un goteo de 1 byte nunca lo dispara."""
    deadline = time.monotonic() + timeout * 3
    buf = bytearray()
    while chunk := r.read(65536):
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError(f"Respuesta mayor de {max_bytes} bytes")
        if time.monotonic() > deadline:
            raise TimeoutError("Tiempo total de descarga agotado")
    return bytes(buf)


def http(url: str, data: dict | None = None, headers: dict | None = None, timeout: int = 60, retries: int = 3,
         max_bytes: int = 10_000_000, allow_private: bool | None = None) -> bytes:
    """allow_private=None: URL fija de confianza (sin comprobar destino); True/False: URL de configuración."""
    body = json.dumps(data).encode() if data is not None else None
    hdrs = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    if body:
        hdrs["Content-Type"] = "application/json"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs)
            opened = (urllib.request.urlopen(req, timeout=timeout) if allow_private is None  # noqa: S310
                      else open_url(req, timeout, allow_private))
            with opened as r:
                return read_capped(r, max_bytes, timeout)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 500, 502, 503, 504) or attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(6 * (attempt + 1))  # NVD devuelve 403 al superar el límite
    raise RuntimeError("unreachable")


def http_json(url: str, data: dict | None = None, headers: dict | None = None, timeout: int = 60,
              max_bytes: int = 10_000_000):
    return json.loads(http(url, data, headers, timeout, max_bytes=max_bytes))


# --- OSV -------------------------------------------------------------------

def osv_batch(queries: list[dict]) -> list[list[tuple[str, str]]]:
    """queries: [{"package": {"ecosystem", "name"}, "version"}] -> [(id, modified)] por consulta."""
    out = []
    for i in range(0, len(queries), 1000):
        res = http_json(f"{OSV}/querybatch", {"queries": queries[i:i + 1000]})
        # ponytail: se ignora next_page_token (>1000 vulns en un solo paquete)
        out += [[(v["id"], v.get("modified", "")) for v in r.get("vulns", [])] for r in res.get("results", [])]
    return out


def osv_vuln(vid: str) -> dict:
    return http_json(f"{OSV}/vulns/{urllib.parse.quote(vid)}")


def parse_osv(v: dict) -> dict:
    score, vector = None, None
    for s in v.get("severity", []):
        if s.get("type") == "CVSS_V3" and (sc := cvss.score_v3(s["score"])) is not None:
            score, vector = sc, s["score"]
            break
        if s.get("type") == "CVSS_V4" and not vector:
            vector = s["score"]
    text_sev = str((v.get("database_specific") or {}).get("severity", "")).upper().replace("MODERATE", "MEDIUM")
    severity = cvss.label(score) if score is not None else (text_sev or "UNKNOWN")
    if score is None and text_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        score = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}[text_sev]  # estimación por etiqueta
    cwes = (v.get("database_specific") or {}).get("cwe_ids") or []
    return {"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary") or v.get("details", "")[:300],
            "details": v.get("details", ""), "cvss": score, "severity": severity, "vector": vector, "cwes": cwes,
            "refs": [r["url"] for r in v.get("references", [])], "published": v.get("published"),
            "modified": v.get("modified"), "source": "osv", "status": "withdrawn" if v.get("withdrawn") else None,
            "raw": v}


def osv_fixed(v: dict, ecosystem: str, name: str, version: str) -> str | None:
    """Versión corregida del rango que contiene la instalada; si no, la más cercana por encima."""
    contained, above = [], []
    for aff in v.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") != name or not ecosystem.startswith(pkg.get("ecosystem", "\0").split(":")[0]):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            introduced = "0"
            for e in rng.get("events", []):
                if "introduced" in e:
                    introduced = e["introduced"]
                elif "fixed" in e and compare(e["fixed"], version) > 0:
                    above.append(e["fixed"])
                    if introduced == "0" or compare(version, introduced) >= 0:
                        contained.append(e["fixed"])
    for pool in (contained, above):
        if pool:
            return min(pool, key=sort_key)
    return None


# --- NVD -------------------------------------------------------------------

def _nvd_pages(params: dict, api_key: str = ""):
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5  # 50 / 5 peticiones por 30 s
    start = 0
    while True:
        # 500 por página mantiene cada respuesta muy por debajo del tope aun con productos enormes (kernel)
        q = urllib.parse.urlencode({**params, "startIndex": start, "resultsPerPage": 500})
        page = http_json(f"{NVD}?{q}", headers=headers, timeout=120, max_bytes=64_000_000)
        yield from page.get("vulnerabilities", [])
        start += page.get("resultsPerPage", 0)
        time.sleep(delay)
        if not page.get("resultsPerPage") or start >= page.get("totalResults", 0):
            return


def nvd_product(vendor: str | None, product: str, api_key: str = ""):
    return _nvd_pages({"virtualMatchString": f"cpe:2.3:*:{vendor or '*'}:{product}"}, api_key)


def nvd_modified(since: dt.datetime, until: dt.datetime, api_key: str = ""):
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    return _nvd_pages({"lastModStartDate": since.strftime(fmt), "lastModEndDate": until.strftime(fmt)}, api_key)


_SKIP_VER = {"", "*", "-", "0", "n/a", "unspecified", "unknown", "all"}


def parse_nvd(item: dict) -> dict:
    c = item["cve"]
    score = vector = None
    severity = "UNKNOWN"
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if ms := metrics.get(key):
            m = next((x for x in ms if x.get("type") == "Primary"), ms[0])
            d = m["cvssData"]
            score, vector = d.get("baseScore"), d.get("vectorString")
            severity = d.get("baseSeverity") or m.get("baseSeverity") or cvss.label(score)
            break
    cpes = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    p = parse_cpe(m["criteria"])
                    cpes.append({"vendor": norm_product(p["vendor"]), "product": norm_product(p["product"]),
                                 "version": p["version"], "start_inc": m.get("versionStartIncluding"),
                                 "start_exc": m.get("versionStartExcluding"), "end_inc": m.get("versionEndIncluding"),
                                 "end_exc": m.get("versionEndExcluding"), "origin": "nvd"})
    if not cpes:  # Aún sin analizar por NVD: datos del CNA (formato CVE 5)
        for block in c.get("affected", []):
            for a in block.get("affectedData", []):
                product = norm_product(a.get("product") or a.get("packageName") or "")
                if not product or product == "n_a":
                    continue
                vendor = norm_product(a.get("vendor") or "")
                for v in a.get("versions", []):
                    if v.get("status") != "affected":
                        continue
                    ver, lt, lte = str(v.get("version", "")), v.get("lessThan"), v.get("lessThanOrEqual")
                    row = {"vendor": vendor, "product": product, "version": None, "start_inc": None,
                           "start_exc": None, "end_inc": None, "end_exc": None, "origin": "cna"}
                    if lt or lte:
                        row["start_inc"] = None if ver.lower() in _SKIP_VER else ver
                        row["end_exc"] = None if str(lt).lower() in _SKIP_VER else lt
                        row["end_inc"] = None if str(lte).lower() in _SKIP_VER else lte
                        if not (row["end_exc"] or row["end_inc"]):  # "< *": desde 'version' en adelante
                            row["start_inc"] = row["start_inc"] or "0"
                    elif ver.lower() not in _SKIP_VER:
                        row["version"] = ver
                    else:
                        continue
                    cpes.append(row)
    kev = {"action": c["cisaRequiredAction"], "due": c.get("cisaActionDue"), "added": c.get("cisaExploitAdd"),
           "name": c.get("cisaVulnerabilityName")} if c.get("cisaExploitAdd") else None
    return {"id": c["id"], "aliases": [], "summary": next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), ""),
            "details": "", "cvss": score, "severity": severity, "vector": vector,
            "cwes": sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                            if d["value"].startswith("CWE-")}),
            "refs": [r["url"] for r in c.get("references", [])][:40], "published": c.get("published"),
            "modified": c.get("lastModified"), "source": "nvd", "status": c.get("vulnStatus"),
            "raw": {"kev": kev}, "cpes": cpes}


# --- KEV / EPSS ------------------------------------------------------------

def kev_catalog() -> list[dict]:
    return http_json(KEV, max_bytes=20_000_000).get("vulnerabilities", [])


def epss(cves: list[str]) -> dict[str, tuple[float, float]]:
    out = {}
    for i in range(0, len(cves), 100):
        res = http_json(f"{EPSS}?cve={','.join(cves[i:i + 100])}")
        out |= {d["cve"]: (float(d["epss"]), float(d["percentile"])) for d in res.get("data", [])}
    return out


# --- Noticias (RSS / Atom) -------------------------------------------------

def feed(url: str) -> list[dict]:
    raw = http(url, headers={"Accept": "application/rss+xml, application/xml"}, timeout=30,
               max_bytes=25_000_000, allow_private=False)  # el feed completo de CISA ronda 5,7 MB
    root = safe_xml(raw)
    items = []
    for it in root.iter():
        tag = it.tag.rsplit("}", 1)[-1]
        if tag not in ("item", "entry"):
            continue
        get = lambda name: next((c for c in it if c.tag.rsplit("}", 1)[-1] == name), None)
        title, link, date = get("title"), get("link"), get("pubDate") or get("updated") or get("published")
        href = (link.get("href") or link.text) if link is not None else None
        desc = get("description") or get("summary")
        if title is not None and href:
            items.append({"title": html.unescape((title.text or "").strip()), "link": href.strip(),
                          "published": (date.text or "").strip() if date is not None else "",
                          # recorte antes del regex: acota el coste con descripciones hostiles
                          "text": html.unescape(re.sub(r"<[^>]{0,1000}>", " ",
                                                       ((desc.text or "") if desc is not None else "")[:20000]))[:2000]})
    return items[:100]
