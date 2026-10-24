"""Ciclo de monitorización: inventario -> cruce con fuentes -> hallazgos -> prioridad -> avisos."""
import datetime as dt
import json
import re
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from . import advice, db, manifests, notify, sources, system, webprobe
from .versions import in_range

LOCK = threading.Lock()
STATE = {"running": False, "phase": "", "last_run": None, "last_duration": None, "next_run": None, "last_error": None}
NVD_PRODUCTS_PER_CYCLE = 25  # sin API key NVD admite ~5 peticiones / 30 s
REFRESH = 6 * 3600
CONF_RANK = {"possible": 0, "probable": 1, "confirmed": 2}
NEWS_STOP = {"http server", "server", "client", "core", "common", "utils", "tools", "update", "driver", "runtime",
             "web", "app", "service", "desktop", "engine", "framework", "library", "windows", "linux", "kernel",
             "python", "java", "node", "react", "chrome", "security", "manager", "helper", "agent", "plugin"}


# --- Inventario --------------------------------------------------------------

def apply_overrides(comps: list[dict]) -> list[dict]:
    """Correcciones manuales de vendor/producto CPE, persistentes entre versiones."""
    overrides = db.get_setting("cpe_overrides") or {}
    for c in comps:
        if o := overrides.get(f"{c['ecosystem']}|{c['name']}"):
            c.update(ecosystem="CPE", vendor=o.get("vendor") or None, product=o["product"])
    return comps


def store_components(target_id: int, comps: list[dict], replace: bool = True) -> None:
    ts = time.time()
    with db.conn() as c:
        for x in apply_overrides(manifests.dedupe(comps)):
            c.execute(
                """INSERT INTO components(target_id, ecosystem, name, version, source, vendor, product, seen_at, active)
                   VALUES(?,?,?,?,?,?,?,?,1)
                   ON CONFLICT(target_id, ecosystem, name, version, source) DO UPDATE SET
                   seen_at=excluded.seen_at, active=1, vendor=excluded.vendor, product=excluded.product""",
                (target_id, x["ecosystem"], x["name"][:300], x["version"][:100], x["source"][:500],
                 x.get("vendor") and manifests.norm_product(x["vendor"])[:120],
                 x.get("product") and manifests.norm_product(x["product"])[:200], ts))
        if replace:
            c.execute("UPDATE components SET active=0 WHERE target_id=? AND seen_at<? AND manual=0", (target_id, ts))


def refresh_target(t: dict) -> bool:
    """True si el inventario está completo. Con errores no se retira nada: un escaneo a medias
    haría pasar por 'resuelto' lo que solo no se pudo leer."""
    errors: list[str] = []
    match t["kind"]:
        case "path" if not manifests.path_allowed(t["location"]):
            comps, errors = [], [f"{t['location']}: fuera de PM_SCAN_ROOTS, no se escanea"]
        case "path" | "upload":
            comps, errors = manifests.scan_path(t["location"])
        case "url":
            comps, errors = webprobe.probe(t["location"])
        case "system":
            comps = system.inventory()["components"]
        case _:
            return True  # agent / manual: los componentes llegan por la API
    store_components(t["id"], comps, replace=not errors)
    with db.conn() as c:
        c.execute("UPDATE targets SET last_scan=?, last_error=? WHERE id=?",
                  (time.time(), "\n".join(errors[:20]) or None, t["id"]))
    return not errors


# --- Persistencia de vulnerabilidades -----------------------------------------

def save_vuln(c, v: dict) -> None:
    c.execute(
        """INSERT INTO vulns(id, aliases, summary, details, cvss, severity, vector, cwes, refs, published, modified, source, status, raw)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET aliases=excluded.aliases, summary=excluded.summary, details=excluded.details,
           cvss=excluded.cvss, severity=excluded.severity, vector=excluded.vector, cwes=excluded.cwes, refs=excluded.refs,
           published=excluded.published, modified=excluded.modified, status=excluded.status, raw=excluded.raw""",
        (v["id"], json.dumps(v["aliases"]), v["summary"][:4000], v["details"][:20000], v["cvss"], v["severity"],
         v["vector"], json.dumps(v["cwes"]), json.dumps(v["refs"]), v["published"], v["modified"], v["source"],
         v["status"], json.dumps(v["raw"])))
    if "cpes" in v:
        c.execute("DELETE FROM vuln_cpes WHERE vuln_id=?", (v["id"],))
        c.executemany("INSERT INTO vuln_cpes VALUES(?,?,?,?,?,?,?,?,?)",
                      [(v["id"], r["vendor"], r["product"], r["version"], r["start_inc"], r["start_exc"],
                        r["end_inc"], r["end_exc"], r["origin"]) for r in v["cpes"]])
    if kev := v["raw"].get("kev"):
        c.execute("INSERT OR IGNORE INTO kev(cve, name, action, due, added) VALUES(?,?,?,?,?)",
                  (v["id"], kev.get("name"), kev.get("action"), kev.get("due"), kev.get("added")))


def upsert_finding(c, comp_id: int, vuln_id: str, confidence: str, fixed: str | None, ts: float) -> None:
    c.execute(
        """INSERT INTO findings(component_id, vuln_id, confidence, fixed_version, first_seen, last_seen)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(component_id, vuln_id) DO UPDATE SET last_seen=excluded.last_seen,
           confidence=excluded.confidence, fixed_version=excluded.fixed_version, resolved_at=NULL,
           status=CASE WHEN status='resolved' THEN 'open' ELSE status END""",
        (comp_id, vuln_id, confidence, fixed, ts, ts))


# --- Cruce con OSV (paquetes de ecosistema) ------------------------------------

def _fetch_osv(vid: str) -> dict | None:
    try:
        return sources.osv_vuln(vid)
    except Exception as e:
        db.log("warn", f"OSV {vid}: {e}")
        return None


def match_osv(comps: list[dict]) -> set[int]:
    todo = [c for c in comps if c["ecosystem"] != "CPE" and c["version"]]
    if not todo:
        return set()
    STATE["phase"] = f"OSV: {len(todo)} paquetes"
    hits = sources.osv_batch([{"package": {"ecosystem": c["ecosystem"], "name": c["name"]}, "version": c["version"]}
                              for c in todo])
    known = {r["id"]: r["modified"] for r in db.rows("SELECT id, modified FROM vulns WHERE source='osv'")}
    need = sorted({vid for row in hits for vid, mod in row if vid not in known or (mod and mod != known[vid])})
    STATE["phase"] = f"OSV: descargando {len(need)} avisos"
    with ThreadPoolExecutor(8) as ex:
        fetched = [v for v in ex.map(_fetch_osv, need) if v]
    with db.conn() as c:
        for v in fetched:
            save_vuln(c, sources.parse_osv(v))
    used = sorted({vid for row in hits for vid, _ in row})
    raw = {r["id"]: json.loads(r["raw"]) for r in
           db.rows("SELECT id, raw FROM vulns WHERE id IN (SELECT value FROM json_each(?))", (json.dumps(used),))}
    ts = time.time()
    with db.conn() as c:
        for comp, row in zip(todo, hits):
            for vid, _ in row:
                v = raw.get(vid)
                if v is None or v.get("withdrawn"):
                    continue
                upsert_finding(c, comp["id"], vid, "confirmed",
                               sources.osv_fixed(v, comp["ecosystem"], comp["name"], comp["version"]), ts)
    return {c["id"] for c in todo}


# --- NVD (software identificado por CPE) ---------------------------------------

def _nvd_key() -> str:
    return db.resolve_secret(db.get_setting("nvd_api_key") or "")


def nvd_products(comps: list[dict]) -> None:
    """Histórico completo de CVE para productos que aún no se han consultado.

    Primero los productos de activos propios (no de agentes) y los más extendidos. Un producto que
    falla espera REFRESH antes de reintentarse y no bloquea al resto de la cola."""
    api = _nvd_key()
    done = db.get_setting("nvd_products") or {}
    failed = db.get_setting("nvd_failed") or {}
    cpe = [c for c in comps if c["ecosystem"] == "CPE" and c["product"]]
    counts = Counter(c["product"] for c in cpe)
    local = {c["product"] for c in cpe if c.get("target_kind") != "agent"}
    todo = sorted((p for p in counts if p not in done and time.time() - failed.get(p, 0) > REFRESH),
                  key=lambda p: (p not in local, -counts[p], p))
    for product in todo[: 500 if api else NVD_PRODUCTS_PER_CYCLE]:
        STATE["phase"] = f"NVD: histórico de {product}"
        try:
            items = [sources.parse_nvd(i) for i in sources.nvd_product(None, product, api)]
        except Exception as e:
            failed[product] = time.time()
            db.set_setting("nvd_failed", failed)
            db.log("warn", f"NVD histórico de {product}: {type(e).__name__}: {e}")
            continue
        with db.conn() as c:
            for v in items:
                if v["status"] != "Rejected":
                    save_vuln(c, v)
        done[product] = time.time()
        failed.pop(product, None)
        db.set_setting("nvd_products", done)
        db.set_setting("nvd_failed", failed)


def keywords(comps: list[dict]) -> dict[str, str]:
    """Términos para buscar en texto libre (CVE sin analizar y noticias) -> producto."""
    out = {}
    for c in comps:
        if c["ecosystem"] == "CPE" and c["product"]:
            for term in {c["product"].replace("_", " "), c["name"].lower()}:
                if len(term) >= 3 and term not in NEWS_STOP and not term.isdigit():
                    out[term] = c["product"]
        elif len(c["name"]) >= 5 and c["name"].lower() not in NEWS_STOP:
            out[c["name"].lower().split(":")[-1].split("/")[-1]] = c["name"]
    return out


def text_hits(text: str, kw: dict[str, str]) -> set[str]:
    # ponytail: búsqueda por palabra completa, O(términos); índice invertido si el inventario pasa de miles
    low = text.lower()
    return {prod for term, prod in kw.items()
            if term in low and re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", low)}


def nvd_incremental(comps: list[dict]) -> None:
    """CVE publicadas o modificadas desde el último sondeo (aviso temprano)."""
    api = _nvd_key()
    end = dt.datetime.now(dt.UTC)
    last = db.get_setting("nvd_last_sync")
    start = dt.datetime.fromtimestamp(last, dt.UTC) if last else end - dt.timedelta(days=3)
    start = max(start - dt.timedelta(minutes=5), end - dt.timedelta(days=119))
    products = {c["product"] for c in comps if c["ecosystem"] == "CPE" and c["product"]}
    cpe_kw = {k: v for k, v in keywords(comps).items() if v in products}
    known = {r["id"] for r in db.rows("SELECT id FROM vulns WHERE source='nvd'")}
    STATE["phase"] = "NVD: novedades"
    with db.conn() as c:
        for item in sources.nvd_modified(start, end, api):
            v = sources.parse_nvd(item)
            if v["status"] == "Rejected":
                continue
            relevant = {r["product"] for r in v["cpes"]} & products
            if not v["cpes"] and (mentioned := text_hits(v["summary"], cpe_kw)):
                v["cpes"] = [{"vendor": "", "product": p, "version": None, "start_inc": None, "start_exc": None,
                              "end_inc": None, "end_exc": None, "origin": "text"} for p in mentioned]
                relevant = mentioned
            if relevant or v["id"] in known:
                save_vuln(c, v)
    db.set_setting("nvd_last_sync", end.timestamp())


def match_cpe(comps: list[dict]) -> set[int]:
    todo = [c for c in comps if c["ecosystem"] == "CPE" and c["product"]]
    ts = time.time()
    with db.conn() as c:
        for comp in todo:
            best: dict[str, tuple[str, str | None]] = {}
            for r in c.execute("SELECT * FROM vuln_cpes WHERE product=?", (comp["product"],)):
                if r["origin"] == "nvd" and r["vendor"] and comp["vendor"] and r["vendor"] != comp["vendor"]:
                    continue
                if r["origin"] == "text":
                    conf = "possible"
                elif comp["version"] and in_range(comp["version"], r["version"], r["start_inc"], r["start_exc"],
                                                  r["end_inc"], r["end_exc"]):
                    conf = "confirmed" if r["origin"] == "nvd" else "probable"
                else:
                    continue
                fixed = r["end_exc"] or (f"> {r['end_inc']}" if r["end_inc"] else None)
                prev = best.get(r["vuln_id"])
                if prev is None or CONF_RANK[conf] > CONF_RANK[prev[0]]:
                    best[r["vuln_id"]] = (conf, fixed)
            for vid, (conf, fixed) in best.items():
                upsert_finding(c, comp["id"], vid, conf, fixed, ts)
    return {c["id"] for c in todo}


def resolve_missing(evaluated: set[int], since: float) -> None:
    """Hallazgos que ya no aparecen (actualizado, desinstalado) pasan a 'resolved'."""
    with db.conn() as c:
        cur = c.execute(
            """UPDATE findings SET status='resolved', resolved_at=? WHERE status IN ('open','acknowledged') AND (
               component_id IN (SELECT id FROM components WHERE active=0)
               OR (last_seen < ? AND component_id IN (SELECT value FROM json_each(?))))""",
            (time.time(), since, json.dumps(sorted(evaluated))))
        resolved = cur.rowcount
    if resolved:  # fuera de la transacción: db.log abre otra conexión
        db.log("info", f"{resolved} hallazgos resueltos (componente actualizado o retirado)")


# --- Enriquecimiento ---------------------------------------------------------

def refresh_kev() -> None:
    if time.time() - (db.get_setting("kev_updated") or 0) < REFRESH:
        return
    STATE["phase"] = "CISA KEV"
    items = sources.kev_catalog()
    with db.conn() as c:
        c.executemany(
            """INSERT INTO kev VALUES(?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET name=excluded.name,
               action=excluded.action, due=excluded.due, added=excluded.added, ransomware=excluded.ransomware, notes=excluded.notes""",
            [(k["cveID"], k.get("vulnerabilityName"), k.get("requiredAction"), k.get("dueDate"), k.get("dateAdded"),
              k.get("knownRansomwareCampaignUse"), k.get("notes")) for k in items])
    db.set_setting("kev_updated", time.time())


def _cves(vuln_id: str, aliases: list[str]) -> list[str]:
    return [x for x in [vuln_id, *aliases] if x.startswith("CVE-")]


def refresh_epss() -> None:
    open_rows = db.rows("""SELECT v.id, v.aliases FROM findings f JOIN vulns v ON v.id=f.vuln_id
                           WHERE f.status IN ('open','acknowledged')""")
    fresh = {r["cve"] for r in db.rows("SELECT cve FROM epss WHERE updated > ?", (time.time() - REFRESH,))}
    todo = sorted({cve for r in open_rows for cve in _cves(r["id"], json.loads(r["aliases"]))} - fresh)
    if not todo:
        return
    STATE["phase"] = f"EPSS: {len(todo)} CVE"
    scores = sources.epss(todo)
    with db.conn() as c:
        c.executemany("INSERT OR REPLACE INTO epss VALUES(?,?,?,?)",
                      [(cve, *scores.get(cve, (None, None)), time.time()) for cve in todo])


FINDING_SQL = """SELECT f.*, v.summary, v.cvss, v.severity, v.cwes, v.refs, v.aliases, v.source AS vuln_source,
  c.name, c.version, c.ecosystem, c.source, c.vendor, c.product, c.ignored, c.target_id, t.name AS target
  FROM findings f JOIN vulns v ON v.id=f.vuln_id JOIN components c ON c.id=f.component_id JOIN targets t ON t.id=c.target_id"""


def enrich(r: dict, kev: dict, epss: dict) -> tuple[dict | None, float | None]:
    cves = _cves(r["vuln_id"], json.loads(r["aliases"]))
    k = next((kev[x] for x in cves if x in kev), None)
    e = max((epss[x] for x in cves if epss.get(x) is not None), default=None)
    return k, e


def reprioritize() -> None:
    kev = {r["cve"]: r for r in db.rows("SELECT * FROM kev")}
    epss = {r["cve"]: r["score"] for r in db.rows("SELECT cve, score FROM epss")}
    rows = db.rows(FINDING_SQL + " WHERE f.status IN ('open','acknowledged')")
    with db.conn() as c:
        for r in rows:
            k, e = enrich(r, kev, epss)
            vuln = {"cwes": json.loads(r["cwes"]), "refs": json.loads(r["refs"])}
            rec = advice.recommendation(r, vuln, r["fixed_version"], k, e, r["confidence"])
            c.execute("UPDATE findings SET priority=?, recommendation=? WHERE id=?",
                      (advice.priority(r["cvss"], k is not None, e, r["confidence"]), json.dumps(rec), r["id"]))


# --- Avisos ------------------------------------------------------------------

def vuln_link(vid: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{vid}" if vid.startswith("CVE-") else f"https://osv.dev/vulnerability/{vid}"


def finding_context(r: dict, kev: dict, epss: dict) -> dict:
    k, e = enrich(r, kev, epss)
    steps = json.loads(r["recommendation"] or "{}").get("steps") or ["-"]
    fix = next((s for s in steps if s.startswith(("Actualiza", "No hay"))), steps[0])
    return {"target": r["target"], "component": r["name"], "version": r["version"] or "?", "vuln_id": r["vuln_id"],
            "severity": r["severity"], "priority": r["priority"].upper(), "cvss": r["cvss"] if r["cvss"] is not None else "n/d",
            "summary": (r["summary"] or "")[:300], "fix": fix,
            "fixed_version": r["fixed_version"] or "sin parche", "kev": "SÍ" if k else "no",
            "epss": f"{e:.0%}" if e is not None else "n/d", "link": vuln_link(r["vuln_id"]),
            "confidence": r["confidence"], "ecosystem": r["ecosystem"]}


def notify_findings(force_ids: list[int] | None = None) -> list[dict]:
    threshold = advice.rank(db.get_setting("notify_min_priority"))
    rows = db.rows(FINDING_SQL + " WHERE f.status='open' AND c.ignored=0 AND c.active=1")
    if force_ids is not None:
        due = [r for r in rows if r["id"] in force_ids]
    else:
        due = [r for r in rows if advice.rank(r["priority"]) >= threshold
               and advice.rank(r["priority"]) > advice.rank(r["notified_priority"])]
    if not due:
        return []
    due.sort(key=lambda r: (-advice.rank(r["priority"]), -(r["cvss"] or 0)))
    kev = {r["cve"]: r for r in db.rows("SELECT * FROM kev")}
    epss = {r["cve"]: r["score"] for r in db.rows("SELECT cve, score FROM epss")}
    template = db.get_setting("notify_template")
    ctxs = [finding_context(r, kev, epss) for r in due]
    body = "\n\n".join(notify.render(template, x) for x in ctxs[:25])
    if len(due) > 25:
        body += f"\n\n... y {len(due) - 25} más. Revisa el panel de PreventiveMeasure."
    subject = notify.render(db.get_setting("notify_digest_header"), {"count": len(due), **ctxs[0]})
    results = notify.dispatch(subject, body, {"findings": ctxs})
    if force_ids is None and (not results or any(r["ok"] for r in results)):
        with db.conn() as c:
            c.executemany("UPDATE findings SET notified_priority=priority WHERE id=?", [(r["id"],) for r in due])
    return results


# --- Noticias ----------------------------------------------------------------

def news_cycle(comps: list[dict]) -> None:
    kw = keywords(comps)
    tracked = {r["vuln_id"] for r in db.rows("SELECT vuln_id FROM findings WHERE status IN ('open','acknowledged')")}
    match = lambda text: sorted(text_hits(text, kw) | (set(re.findall(r"CVE-\d{4}-\d{4,}", text)) & tracked))
    baseline = set(db.get_setting("feeds_baseline") or [])
    for url in db.get_setting("feeds") or []:
        STATE["phase"] = f"Noticias: {url[:60]}"
        try:
            items = sources.feed(url)
        except Exception as e:
            u = urllib.parse.urlsplit(url)  # sin usuario ni query: pueden llevar credenciales
            db.log("warn", f"Feed {u.scheme}://{u.hostname}{u.path}: {type(e).__name__}: {e}")
            continue
        first = url not in baseline  # la primera lectura no avisa del histórico
        with db.conn() as c:
            for it in items:
                matched = match(f"{it['title']} {it['text']}")
                c.execute("""INSERT OR IGNORE INTO news(link, title, feed, published, matched, fetched, notified, body)
                             VALUES(?,?,?,?,?,?,?,?)""",
                          (it["link"][:1000], it["title"][:500], url, it["published"], json.dumps(matched),
                           time.time(), 1 if first or not matched else 0, it["text"]))
        baseline.add(url)
    db.set_setting("feeds_baseline", sorted(baseline))
    # El inventario cambia: una noticia reciente puede afectar a algo recién añadido
    with db.conn() as c:
        for n in c.execute("SELECT id, title, body, matched FROM news WHERE fetched > ?", (time.time() - 14 * 86400,)).fetchall():
            matched = match(f"{n['title']} {n['body']}")
            if set(matched) - set(json.loads(n["matched"])):
                c.execute("UPDATE news SET matched=?, notified=0 WHERE id=?", (json.dumps(matched), n["id"]))
    pending = db.rows("SELECT * FROM news WHERE notified=0 ORDER BY id")
    if pending and db.get_setting("notify_news"):
        body = "\n\n".join(f"- {n['title']}\n  Afecta a: {', '.join(json.loads(n['matched']))}\n  {n['link']}"
                           for n in pending[:20])
        notify.dispatch(f"PreventiveMeasure: {len(pending)} noticias de seguridad sobre tu inventario", body,
                        {"news": [{k: n[k] for k in ("title", "link", "matched")} for n in pending]})
    with db.conn() as c:
        c.execute("UPDATE news SET notified=1 WHERE notified=0")


# --- Orquestación ------------------------------------------------------------

def active_components(target_ids: list[int] | None = None) -> list[dict]:
    sql = """SELECT c.*, t.kind AS target_kind FROM components c JOIN targets t ON t.id=c.target_id
             WHERE c.active=1 AND t.enabled=1"""
    if target_ids is None:
        return db.rows(sql)
    return db.rows(sql + " AND t.id IN (SELECT value FROM json_each(?))", (json.dumps(target_ids),))


def _step(name: str, fn, *args) -> None:
    try:
        fn(*args)
    except Exception as e:  # una fuente caída no detiene el ciclo
        db.log("error", f"{name}: {type(e).__name__}: {e}")
        STATE["last_error"] = f"{name}: {e}"


def run_cycle(target_ids: list[int] | None = None, trigger: str = "programado") -> bool:
    if not LOCK.acquire(blocking=False):
        return False
    start = time.time()
    STATE.update(running=True, last_error=None)
    full = target_ids is None
    try:
        sql = "SELECT * FROM targets WHERE enabled=1"
        targets = db.rows(sql) if full else db.rows(sql + " AND id IN (SELECT value FROM json_each(?))", (json.dumps(target_ids),))
        incomplete: set[int] = set()
        for t in targets:
            STATE["phase"] = f"Inventario: {t['name']}"
            try:
                if not refresh_target(t):
                    incomplete.add(t["id"])
            except Exception as e:
                incomplete.add(t["id"])
                db.log("error", f"Inventario {t['name']}: {type(e).__name__}: {e}")
                with db.conn() as c:
                    c.execute("UPDATE targets SET last_error=? WHERE id=?", (f"{type(e).__name__}: {e}", t["id"]))
        comps = active_components(None if full else target_ids)
        evaluated: set[int] = set()

        def osv():
            evaluated.update(match_osv(comps))

        _step("OSV", osv)
        _step("CISA KEV", refresh_kev)
        _step("NVD histórico", nvd_products, comps)
        if full:
            _step("NVD novedades", nvd_incremental, active_components())
        evaluated |= match_cpe(comps)
        resolve_missing(evaluated - {c["id"] for c in comps if c["target_id"] in incomplete}, start)
        _step("EPSS", refresh_epss)
        reprioritize()
        if full:
            _step("Noticias", news_cycle, comps)
        _step("Avisos", notify_findings)
        with db.conn() as c:
            c.execute("DELETE FROM components WHERE active=0 AND seen_at < ?", (time.time() - 30 * 86400,))
        n = db.rows("SELECT COUNT(*) AS n FROM findings WHERE status='open'")[0]["n"]
        db.log("info", f"Ciclo {trigger} completado en {time.time() - start:.0f}s: {len(comps)} componentes, {n} hallazgos abiertos")
    except Exception as e:
        STATE["last_error"] = f"{type(e).__name__}: {e}"
        db.log("error", f"Ciclo {trigger} abortado: {STATE['last_error']}")
    finally:
        STATE.update(running=False, phase="", last_run=time.time(), last_duration=time.time() - start)
        LOCK.release()
    return True


PENDING: set[int] = set()  # activos que pidieron análisis mientras había un ciclo en marcha


def _run_and_drain(target_ids: list[int] | None, reason: str) -> None:
    run_cycle(target_ids, reason)
    while PENDING and not LOCK.locked():
        ids = sorted(PENDING)
        PENDING.clear()
        run_cycle(ids, "pendiente")


def trigger(target_ids: list[int] | None = None, reason: str = "manual") -> bool:
    """False si ya hay un ciclo; en ese caso los activos concretos quedan en cola."""
    if LOCK.locked():
        PENDING.update(target_ids or [])
        return False
    threading.Thread(target=_run_and_drain, args=(target_ids, reason), daemon=True).start()
    return True


def scheduler(stop: threading.Event) -> None:
    while not stop.is_set():
        interval = min(max(int(db.get_setting("interval_minutes") or 30), 5), 1440) * 60
        STATE["next_run"] = (STATE["last_run"] or 0) + interval
        if time.time() >= STATE["next_run"] and not LOCK.locked():
            _run_and_drain(None, "programado")
        stop.wait(15)
