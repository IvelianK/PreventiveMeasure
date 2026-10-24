import csv
import hmac
import io
import json
import os
import re
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import advice, db, engine, manifests, notify
from .manifests import norm_product

STATIC = Path(__file__).parent / "static"
MASK = "********"
MAX_UPLOAD = 300 * 1024 * 1024
BODY_LIMITS = {"/api/targets/upload": MAX_UPLOAD, "/api/agent/ingest": 32 * 1024 * 1024}
STOP = threading.Event()
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@asynccontextmanager
async def lifespan(_app):
    db.init()
    threading.Thread(target=engine.scheduler, args=(STOP,), daemon=True, name="scheduler").start()
    yield
    STOP.set()


app = FastAPI(title="PreventiveMeasure", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class _TooLarge(Exception):
    pass


class BodyLimit:
    """Corta cuerpos grandes antes de leerlos: FastAPI parsea el body antes de comprobar el token,
    así que sin esto un POST anónimo de varios GB llega entero a memoria."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = BODY_LIMITS.get(scope["path"], 1024 * 1024)
        headers = dict(scope["headers"])
        if int(headers.get(b"content-length", b"0") or 0) > limit:
            return await JSONResponse({"detail": "Cuerpo demasiado grande"}, 413)(scope, receive, send)
        seen, started = 0, False

        async def capped():  # cubre también envíos chunked sin Content-Length
            nonlocal seen
            msg = await receive()
            seen += len(msg.get("body", b""))
            if seen > limit:
                raise _TooLarge
            return msg

        async def tracking_send(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)

        try:
            await self.app(scope, capped, tracking_send)
        except _TooLarge:
            if not started:
                await JSONResponse({"detail": "Cuerpo demasiado grande"}, 413)(scope, receive, send)


app.add_middleware(BodyLimit)
# Anti DNS rebinding: con bind en loopback solo se aceptan esos nombres; en red, PM_ALLOWED_HOSTS explícito
if hosts := os.environ.get("PM_ALLOWED_HOSTS") or (
        "127.0.0.1,localhost,[::1]" if os.environ.get("PM_BIND_HOST") in LOOPBACK else ""):
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[h.strip() for h in hosts.split(",") if h.strip()])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                   "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store" if request.url.path.startswith("/api/") else "no-cache",
    })
    return resp


def _token_ok(request: Request, *keys: str) -> bool:
    header = request.headers.get("authorization", "")
    given = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not given:
        return False
    for k in keys:
        if k == "admin_token":
            if env := os.environ.get("PM_ADMIN_TOKEN", "").strip():
                if hmac.compare_digest(given.encode(), env.encode()):
                    return True
            elif hmac.compare_digest(db.token_hash(given), str(db.get_setting("admin_token_sha256"))):
                return True
        elif hmac.compare_digest(given.encode(), str(db.get_setting(k)).encode()):
            return True
    return False


_AUTH_FAILS: dict[str, list] = {}  # ip -> [inicio de ventana, fallos]


def _auth_failed(request: Request) -> None:
    """Un evento por IP y minuto con el recuento: deja rastro de fuerza bruta sin inundar el registro."""
    ip, now = request.client.host if request.client else "?", time.time()
    window = _AUTH_FAILS.setdefault(ip, [now, 0])
    if now - window[0] > 60:
        if window[1] > 1:
            db.log("warn", f"{window[1]} peticiones con token no válido desde {ip} en el último minuto")
        window[:] = [now, 0]
    window[1] += 1
    if window[1] == 1:
        db.log("warn", f"Token no válido desde {ip} en {request.url.path}")
    raise HTTPException(401, "Token no válido")


def admin(request: Request) -> None:
    if not _token_ok(request, "admin_token"):
        _auth_failed(request)


def agent(request: Request) -> None:
    if not _token_ok(request, "agent_token", "admin_token"):
        _auth_failed(request)


A = [Depends(admin)]


# --- Modelos -----------------------------------------------------------------

class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["path", "url", "system", "manual"]
    location: str = Field(default="", max_length=2000)

    @field_validator("location")
    @classmethod
    def strip(cls, v: str) -> str:
        return v.strip()


class TargetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None


class ComponentIn(BaseModel):
    ecosystem: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(default="", max_length=100)
    source: str = Field(default="", max_length=500)
    vendor: str | None = Field(default=None, max_length=120)
    product: str | None = Field(default=None, max_length=200)


class ComponentPatch(BaseModel):
    ignored: bool | None = None
    vendor: str | None = Field(default=None, max_length=120)
    product: str | None = Field(default=None, max_length=200)


class FindingPatch(BaseModel):
    status: Literal["open", "acknowledged", "ignored", "resolved"] | None = None
    note: str | None = Field(default=None, max_length=2000)


class AgentIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=200)
    os: str = Field(default="", max_length=200)
    components: list[ComponentIn] = Field(max_length=100_000)


class SettingsIn(BaseModel):
    interval_minutes: int | None = Field(default=None, ge=5, le=1440)
    notify_min_priority: Literal["low", "medium", "high", "critical"] | None = None
    notify_template: str | None = Field(default=None, min_length=1, max_length=4000)
    notify_digest_header: str | None = Field(default=None, min_length=1, max_length=300)
    notify_news: bool | None = None
    nvd_api_key: str | None = Field(default=None, max_length=200)
    feeds: list[str] | None = Field(default=None, max_length=50)
    channels: dict[str, dict[str, str | int | bool]] | None = None

    @field_validator("feeds")
    @classmethod
    def http_feeds(cls, v):
        if v and any(not re.match(r"^https?://", f) for f in v):
            raise ValueError("Los feeds deben ser URLs http(s)")
        return v


class PreviewIn(BaseModel):
    template: str = Field(max_length=4000)


# --- Estado y objetivos ------------------------------------------------------

@app.get("/api/status", dependencies=A)
def status():
    counts = db.rows("""SELECT f.priority, COUNT(*) AS n FROM findings f JOIN components c ON c.id=f.component_id
                        WHERE f.status='open' AND c.ignored=0 AND c.active=1 GROUP BY f.priority""")
    return {
        **engine.STATE,
        "interval_minutes": db.get_setting("interval_minutes"),
        "open": {r["priority"]: r["n"] for r in counts},
        "targets": db.rows("SELECT COUNT(*) AS n FROM targets")[0]["n"],
        "components": db.rows("SELECT COUNT(*) AS n FROM components WHERE active=1")[0]["n"],
        "kev_open": db.rows("""SELECT COUNT(DISTINCT f.id) AS n FROM findings f JOIN vulns v ON v.id=f.vuln_id
                               JOIN kev k ON k.cve=v.id OR v.aliases LIKE '%"' || k.cve || '"%'
                               WHERE f.status='open'""")[0]["n"],
        "channels": [n for n, c in db.channels().items() if c.get("enabled")],
        "nvd_key": bool(db.resolve_secret(db.get_setting("nvd_api_key") or "")),
        "nvd_pending": len({c["product"] for c in engine.active_components() if c["ecosystem"] == "CPE" and c["product"]}
                           - set(db.get_setting("nvd_products") or {})),
        "trend": db.rows("""SELECT date(first_seen, 'unixepoch') AS day, COUNT(*) AS n FROM findings
                            WHERE first_seen > ? GROUP BY day ORDER BY day""", (time.time() - 30 * 86400,)),
    }


@app.post("/api/scan", dependencies=A)
def scan_all():
    if not engine.trigger(None, "manual"):
        raise HTTPException(409, "Ya hay un ciclo en marcha")
    return {"ok": True}


@app.get("/api/targets", dependencies=A)
def list_targets():
    return db.rows("""SELECT t.*,
        (SELECT COUNT(*) FROM components c WHERE c.target_id=t.id AND c.active=1) AS components,
        (SELECT COUNT(*) FROM findings f JOIN components c ON c.id=f.component_id
          WHERE c.target_id=t.id AND f.status='open' AND c.ignored=0 AND c.active=1) AS open_findings,
        (SELECT MAX(CASE f.priority WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END)
          FROM findings f JOIN components c ON c.id=f.component_id
          WHERE c.target_id=t.id AND f.status='open' AND c.ignored=0 AND c.active=1) AS worst
        FROM targets t ORDER BY t.name""")


def _new_target(name: str, kind: str, location: str, meta: dict | None = None) -> int:
    with db.conn() as c:
        return c.execute("INSERT INTO targets(name, kind, location, created_at, meta) VALUES(?,?,?,?,?)",
                         (name, kind, location, time.time(), json.dumps(meta or {}))).lastrowid


@app.post("/api/targets", dependencies=A)
def add_target(t: TargetIn):
    location = t.location
    match t.kind:
        case "path":
            scoped = manifests.scoped_path(location)
            if scoped is None:
                raise HTTPException(400, "Configura PM_SCAN_ROOTS; ruta fuera de las carpetas permitidas")
            if not scoped.exists():
                raise HTTPException(400, "La ruta no existe en el servidor")
            location = str(scoped)
        case "url":
            if not re.match(r"^https?://[^\s/]+", location):
                raise HTTPException(400, "URL no válida (http/https)")
    tid = _new_target(t.name, t.kind, location)
    if t.kind != "manual":
        engine.trigger([tid], "alta de activo")
    return {"id": tid}


@app.post("/api/targets/upload", dependencies=A)
async def upload_target(request: Request, name: str, filename: str):
    if not (stored := manifests.upload_name(filename)):
        raise HTTPException(400, "Tipo de fichero no reconocido: sube un lockfile, manifiesto, SBOM, APK, AAB o IPA")
    # Carpeta aleatoria + nombre constante: el nombre del cliente nunca forma parte de la ruta
    folder = db.DATA_DIR / "uploads" / uuid.uuid4().hex
    folder.mkdir(mode=0o700)
    dest = folder / stored
    safe = re.sub(r"[^\w.\-]", "_", Path(filename).name)[:120]  # solo para mostrarlo en el panel
    size = 0
    with dest.open("wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_UPLOAD:
                f.close()
                dest.unlink(missing_ok=True)
                folder.rmdir()
                raise HTTPException(413, "Fichero demasiado grande (máx. 300 MB)")
            f.write(chunk)
    tid = _new_target(name[:120] or safe, "upload", str(dest), {"filename": safe})
    engine.trigger([tid], "subida de fichero")
    return {"id": tid}


@app.patch("/api/targets/{tid}", dependencies=A)
def patch_target(tid: int, p: TargetPatch):
    with db.conn() as c:
        if p.name is not None:
            c.execute("UPDATE targets SET name=? WHERE id=?", (p.name, tid))
        if p.enabled is not None:
            c.execute("UPDATE targets SET enabled=? WHERE id=?", (int(p.enabled), tid))
    return {"ok": True}


@app.delete("/api/targets/{tid}", dependencies=A)
def delete_target(tid: int):
    t = db.rows("SELECT * FROM targets WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404)
    stored = None
    if t[0]["kind"] == "upload":
        stored = Path(t[0]["location"])
        uploads = (db.DATA_DIR / "uploads").resolve()
        resolved = stored.resolve()
        if resolved == uploads or not resolved.is_relative_to(uploads):
            raise HTTPException(400, "Ruta de subida fuera de data/uploads")
    with db.conn() as c:
        c.execute("DELETE FROM findings WHERE component_id IN (SELECT id FROM components WHERE target_id=?)", (tid,))
        c.execute("DELETE FROM targets WHERE id=?", (tid,))
    if stored is not None:
        stored.unlink(missing_ok=True)
        if stored.parent.parent == uploads and re.fullmatch(r"[0-9a-f]{32}", stored.parent.name):
            stored.parent.rmdir()
    return {"ok": True}


@app.post("/api/targets/{tid}/scan", dependencies=A)
def scan_target(tid: int):
    return {"ok": True, "queued": not engine.trigger([tid], "recomprobación")}


# --- Componentes -------------------------------------------------------------

@app.get("/api/targets/{tid}/components", dependencies=A)
def list_components(tid: int):
    return db.rows("""SELECT c.*, (SELECT COUNT(*) FROM findings f WHERE f.component_id=c.id AND f.status='open') AS open_findings
                      FROM components c WHERE c.target_id=? AND c.active=1 ORDER BY open_findings DESC, c.name""", (tid,))


@app.post("/api/targets/{tid}/components", dependencies=A)
def add_component(tid: int, comp: ComponentIn):
    if not db.rows("SELECT id FROM targets WHERE id=?", (tid,)):
        raise HTTPException(404)
    product = comp.product or (comp.name if comp.ecosystem == "CPE" else None)
    with db.conn() as c:
        c.execute("""INSERT OR IGNORE INTO components(target_id, ecosystem, name, version, source, vendor, product, manual, seen_at)
                     VALUES(?,?,?,?,?,?,?,1,?)""",
                  (tid, comp.ecosystem, comp.name, comp.version, comp.source or "manual",
                   norm_product(comp.vendor) if comp.vendor else None, norm_product(product) if product else None, time.time()))
    engine.trigger([tid], "componente manual")
    return {"ok": True}


@app.patch("/api/components/{cid}", dependencies=A)
def patch_component(cid: int, p: ComponentPatch):
    rows = db.rows("SELECT * FROM components WHERE id=?", (cid,))
    if not rows:
        raise HTTPException(404)
    comp = rows[0]
    with db.conn() as c:
        if p.ignored is not None:
            c.execute("UPDATE components SET ignored=? WHERE id=?", (int(p.ignored), cid))
        if p.product:
            vendor = norm_product(p.vendor) if p.vendor else None
            c.execute("UPDATE components SET ecosystem='CPE', vendor=?, product=? WHERE id=?",
                      (vendor, norm_product(p.product), cid))
            overrides = db.get_setting("cpe_overrides") or {}
            overrides[f"{comp['ecosystem']}|{comp['name']}"] = {"vendor": vendor, "product": norm_product(p.product)}
            db.set_setting("cpe_overrides", overrides)
    if p.product:
        engine.trigger([comp["target_id"]], "corrección de CPE")
    return {"ok": True}


@app.delete("/api/components/{cid}", dependencies=A)
def delete_component(cid: int):
    with db.conn() as c:
        c.execute("DELETE FROM findings WHERE component_id=?", (cid,))
        c.execute("DELETE FROM components WHERE id=? AND manual=1", (cid,))
    return {"ok": True}


# --- Hallazgos ---------------------------------------------------------------

def _finding_rows(where: str, args: tuple) -> list[dict]:
    kev = {r["cve"]: r for r in db.rows("SELECT * FROM kev")}
    epss = {r["cve"]: r["score"] for r in db.rows("SELECT cve, score FROM epss")}
    out = []
    for r in db.rows(engine.FINDING_SQL + where, args):
        k, e = engine.enrich(r, kev, epss)
        r.update(kev=k, epss=e, link=engine.vuln_link(r["vuln_id"]), recommendation=json.loads(r["recommendation"]),
                 aliases=json.loads(r["aliases"]), cwes=json.loads(r["cwes"]), refs=json.loads(r["refs"]))
        out.append(r)
    return out


@app.get("/api/findings", dependencies=A)
def list_findings(status: str = "open", target_id: int | None = None, limit: int = 2000):
    where, args = " WHERE c.ignored=0", []
    if status != "all":
        where += " AND f.status=?"
        args.append(status)
    if target_id is not None:
        where += " AND c.target_id=?"
        args.append(target_id)
    where += """ ORDER BY CASE f.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 v.cvss DESC, f.first_seen DESC LIMIT ?"""
    args.append(min(max(limit, 1), 10000))
    rows = _finding_rows(where, tuple(args))
    # Dentro de cada prioridad: explotadas activamente, luego probabilidad EPSS, luego CVSS
    rows.sort(key=lambda r: (-advice.rank(r["priority"]), r["kev"] is None, -(r["epss"] or 0), -(r["cvss"] or 0)))
    return rows


@app.get("/api/findings/{fid}", dependencies=A)
def get_finding(fid: int):
    rows = _finding_rows(" WHERE f.id=?", (fid,))
    if not rows:
        raise HTTPException(404)
    r = rows[0]
    v = db.rows("SELECT details, vector, published, modified, status FROM vulns WHERE id=?", (r["vuln_id"],))[0]
    return {**r, **{f"vuln_{k}": val for k, val in v.items()}}


@app.patch("/api/findings/{fid}", dependencies=A)
def patch_finding(fid: int, p: FindingPatch):
    with db.conn() as c:
        if p.status:
            c.execute("UPDATE findings SET status=?, resolved_at=? WHERE id=?",
                      (p.status, time.time() if p.status == "resolved" else None, fid))
        if p.note is not None:
            c.execute("UPDATE findings SET note=? WHERE id=?", (p.note, fid))
    return {"ok": True}


@app.post("/api/findings/{fid}/recheck", dependencies=A)
def recheck_finding(fid: int):
    rows = db.rows("SELECT c.target_id FROM findings f JOIN components c ON c.id=f.component_id WHERE f.id=?", (fid,))
    if not rows:
        raise HTTPException(404)
    return {"ok": True, "queued": not engine.trigger([rows[0]["target_id"]], "recomprobación de hallazgo")}


@app.post("/api/findings/{fid}/notify", dependencies=A)
def renotify(fid: int):
    return {"results": engine.notify_findings([fid])}


@app.get("/api/export/findings.csv", dependencies=A)
def export_csv(status: str = "open"):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["prioridad", "vulnerabilidad", "cvss", "kev", "epss", "activo", "componente", "version",
                "version_corregida", "confianza", "estado", "detectado", "recomendacion"])
    formula = ("=", "+", "-", "@", "\t", "\r", "\n")  # inyección de fórmulas, también tras espacios
    cell = lambda v: f"'{v}" if isinstance(v, str) and (v[:1] in formula or v.lstrip()[:1] in formula) else v
    for r in list_findings(status=status, limit=10000):
        w.writerow([cell(v) for v in (
            r["priority"], r["vuln_id"], r["cvss"], "si" if r["kev"] else "no", r["epss"], r["target"], r["name"],
            r["version"], r["fixed_version"], r["confidence"], r["status"],
            time.strftime("%Y-%m-%d %H:%M", time.localtime(r["first_seen"])),
            " | ".join(r["recommendation"].get("steps", [])))])
    text = buf.getvalue()
    return Response(text, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=preventivemeasure-hallazgos.csv"})


# --- Noticias y registro -----------------------------------------------------

@app.get("/api/news", dependencies=A)
def list_news(only_matched: bool = False):
    where = " WHERE matched != '[]'" if only_matched else ""
    rows = db.rows(f"SELECT * FROM news{where} ORDER BY id DESC LIMIT 300")
    for r in rows:
        r["matched"] = json.loads(r["matched"])
    return rows


@app.get("/api/events", dependencies=A)
def list_events(limit: int = 300):
    return db.rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 5000),))


# --- Ajustes y avisos --------------------------------------------------------

def _masked_channels() -> dict:
    return {name: {k: (MASK if k in db.SECRET_FIELDS and v else v) for k, v in cfg.items()}
            for name, cfg in db.channels().items()}


@app.get("/api/settings", dependencies=A)
def get_settings():
    return {
        **{k: db.get_setting(k) for k in ("interval_minutes", "notify_min_priority", "notify_template",
                                          "notify_digest_header", "notify_news", "feeds")},
        "nvd_api_key": MASK if db.get_setting("nvd_api_key") else "",
        "channels": _masked_channels(),
        "agent_token": db.get_setting("agent_token"),
        "variables": ["target", "component", "version", "vuln_id", "severity", "priority", "cvss", "summary", "fix",
                      "fixed_version", "kev", "epss", "link", "confidence", "ecosystem", "count"],
    }


@app.put("/api/settings", dependencies=A)
def put_settings(s: SettingsIn):
    data = s.model_dump(exclude_none=True)
    if (key := data.pop("nvd_api_key", None)) is not None and key != MASK:
        db.set_setting("nvd_api_key", key)
    if (incoming := data.pop("channels", None)) is not None:
        current = db.channels()
        for name, cfg in incoming.items():
            if name not in current:
                raise HTTPException(400, f"Canal desconocido: {name}")
            for k, v in cfg.items():
                if k not in current[name]:
                    raise HTTPException(400, f"Campo desconocido: {name}.{k}")
                if not (k in db.SECRET_FIELDS and v == MASK):
                    current[name][k] = v
        db.set_setting("channels", current)
    for k, v in data.items():
        db.set_setting(k, v)
    return get_settings()


@app.post("/api/settings/rotate-agent-token", dependencies=A)
def rotate_agent_token():
    db.set_setting("agent_token", secrets.token_urlsafe(32))
    return {"agent_token": db.get_setting("agent_token")}


SAMPLE = {"target": "web-produccion", "component": "php", "version": "8.1.2", "vuln_id": "CVE-2026-00000",
          "severity": "CRITICAL", "priority": "CRITICAL", "cvss": 9.8, "summary": "Ejecución remota de código en PHP...",
          "fix": "Actualiza php de 8.1.2 a 8.1.31 o superior.", "fixed_version": "8.1.31", "kev": "SÍ", "epss": "87%",
          "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-00000", "confidence": "confirmed", "ecosystem": "CPE", "count": 1}


@app.post("/api/settings/preview", dependencies=A)
def preview(p: PreviewIn):
    return {"text": notify.render(p.template, SAMPLE)}


@app.post("/api/notify/test/{channel}", dependencies=A)
def test_channel(channel: str):
    if channel not in db.channels():
        raise HTTPException(404)
    text = notify.render(db.get_setting("notify_template"), SAMPLE)
    return {"results": notify.dispatch("PreventiveMeasure: mensaje de prueba", text, {"test": True}, only=channel)}


# --- Agente remoto -----------------------------------------------------------

@app.post("/api/agent/ingest", dependencies=[Depends(agent)])
def agent_ingest(a: AgentIn):
    rows = db.rows("SELECT id, last_scan FROM targets WHERE kind='agent' AND location=?", (a.hostname,))
    if rows and time.time() - (rows[0]["last_scan"] or 0) < 60:
        # ponytail: token compartido entre agentes; token por agente si alguno puede estar comprometido
        raise HTTPException(429, "Envío demasiado frecuente (mínimo 60 s)", headers={"Retry-After": "60"})
    tid = rows[0]["id"] if rows else _new_target(a.hostname, "agent", a.hostname, {"os": a.os})
    engine.store_components(tid, [c.model_dump() for c in a.components])
    with db.conn() as c:
        c.execute("UPDATE targets SET last_scan=?, last_error=NULL, meta=? WHERE id=?",
                  (time.time(), json.dumps({"os": a.os}), tid))
    engine.trigger([tid], f"agente {a.hostname}")
    return {"target_id": tid, "components": len(a.components)}


# --- Frontend ----------------------------------------------------------------

app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
