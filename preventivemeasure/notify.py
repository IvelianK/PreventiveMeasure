"""Canales de aviso: email, Telegram, WhatsApp (Twilio / CallMeBot), Discord, Slack, Teams, ntfy y webhook."""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import smtplib
import socket
import ssl
import string
import urllib.parse
from email.message import EmailMessage

from . import db
from .sources import ALWAYS_BLOCKED

UA = {"User-Agent": "PreventiveMeasure/1.0"}


def render(template: str, ctx: dict) -> str:
    return string.Template(template).safe_substitute({k: "" if v is None else v for k, v in ctx.items()})


def _request(method: str, url: str, body: bytes | None, headers: dict, timeout: int = 20) -> None:
    """Conecta a una IP validada una sola vez, sin proxy ni redirecciones."""
    if not isinstance(url, str) or url != url.strip() or any(ord(ch) < 32 for ch in url):
        raise ValueError("URL de aviso no válida")
    parsed = urllib.parse.urlsplit(url)
    private = os.environ.get("PM_ALLOW_PRIVATE_NOTIFICATIONS") == "1"
    if (parsed.scheme != "https" and not (private and parsed.scheme == "http")) or not parsed.hostname:
        raise ValueError("Los avisos requieren HTTPS; HTTP privado exige PM_ALLOW_PRIVATE_NOTIFICATIONS=1")
    if parsed.username or parsed.password or parsed.hostname.rstrip(".").lower() == "metadata.google.internal":
        raise ValueError("Destino de aviso no permitido")
    host = parsed.hostname.encode("idna").decode("ascii")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    selected = None
    for family, kind, protocol, _, address in addresses:
        ip = ipaddress.ip_address(address[0].split("%")[0])
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if (any(ip in network for network in ALWAYS_BLOCKED) or (not private and not ip.is_global)
                or (parsed.scheme == "http" and ip.is_global)):
            raise ValueError("Destino de aviso bloqueado")
        if selected is None:
            selected = family, kind, protocol, address
    if selected is None:
        raise ValueError("Destino de aviso sin direcciones")

    family, kind, protocol, address = selected
    raw = socket.socket(family, kind, protocol)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        raw.settimeout(timeout)
        raw.connect(address)  # la IP conectada es exactamente la validada; no se resuelve de nuevo
        connection.sock = (ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                           if parsed.scheme == "https" else raw)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(method, path, body=body, headers={**UA, **headers})
        response = connection.getresponse()
        if response.status >= 300:  # no seguir redirecciones hacia la red interna
            raise RuntimeError(f"El destino de aviso respondió HTTP {response.status}")
        response.read(1024)
    finally:
        connection.close()
        raw.close()


def _post(url: str, body: bytes, headers: dict, timeout: int = 20) -> None:
    _request("POST", url, body, headers, timeout)


def _json(url: str, payload: dict, headers: dict | None = None) -> None:
    _post(url, json.dumps(payload).encode(), {"Content-Type": "application/json", **(headers or {})})


def _chunks(text: str, size: int) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]


def send(name: str, cfg: dict, subject: str, text: str, payload: dict | None = None) -> None:
    s = resolved(cfg)
    match name:
        case "email":
            msg = EmailMessage()
            msg["Subject"], msg["From"] = subject, s["sender"] or s["user"]
            msg["To"] = ", ".join(a.strip() for a in s["to"].split(",") if a.strip())
            msg.set_content(text)
            ctx = ssl.create_default_context()
            port = int(s.get("port") or 587)
            if s.get("security") == "ssl":
                smtp = smtplib.SMTP_SSL(s["host"], port, context=ctx, timeout=30)
            else:
                smtp = smtplib.SMTP(s["host"], port, timeout=30)
                if s.get("security", "starttls") == "starttls":
                    smtp.starttls(context=ctx)
            with smtp:
                if s.get("user"):
                    smtp.login(s["user"], s["password"])
                smtp.send_message(msg)
        case "telegram":
            for part in _chunks(f"{subject}\n\n{text}", 4000):
                _json(f"https://api.telegram.org/bot{s['bot_token']}/sendMessage",
                      {"chat_id": s["chat_id"], "text": part, "disable_web_page_preview": True})
        case "whatsapp_twilio":
            auth = base64.b64encode(f"{s['account_sid']}:{s['auth_token']}".encode()).decode()
            wa = lambda n: n if n.startswith("whatsapp:") else f"whatsapp:{n}"
            for part in _chunks(f"*{subject}*\n\n{text}", 1500):
                body = urllib.parse.urlencode({"From": wa(s["from"]), "To": wa(s["to"]), "Body": part}).encode()
                _post(f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(s['account_sid'])}/Messages.json",
                      body, {"Authorization": f"Basic {auth}", "Content-Type": "application/x-www-form-urlencoded"})
        case "whatsapp_callmebot":
            for part in _chunks(f"*{subject}*\n\n{text}", 1500):
                q = urllib.parse.urlencode({"phone": s["phone"], "text": part, "apikey": s["apikey"]})
                _request("GET", f"https://api.callmebot.com/whatsapp.php?{q}", None, {}, 30)
        case "discord":
            for part in _chunks(f"**{subject}**\n{text}", 1900):
                # Los resúmenes de CVE y titulares son de terceros: sin @everyone/@here inyectados
                _json(s["webhook_url"], {"content": part, "allowed_mentions": {"parse": []}})
        case "slack":
            _json(s["webhook_url"], {"text": f"*{subject}*\n{text}"})
        case "teams":
            _json(s["webhook_url"], {"text": f"**{subject}**\n\n{text}"})
        case "ntfy":
            headers = {"Title": subject.encode("ascii", "replace").decode(), "Priority": "high", "Tags": "warning"}
            if s.get("token"):
                headers["Authorization"] = f"Bearer {s['token']}"
            _post(f"{s['server'].rstrip('/')}/{urllib.parse.quote(s['topic'])}", text.encode(), headers)
        case "webhook":
            body = json.dumps({"subject": subject, "text": text, **(payload or {})}).encode()
            headers = {"Content-Type": "application/json"}
            if s.get("secret"):
                sig = hmac.new(s["secret"].encode(), body, hashlib.sha256).hexdigest()
                headers["X-PreventiveMeasure-Signature"] = f"sha256={sig}"
            _post(s["url"], body, headers)
        case _:
            raise ValueError(f"Canal desconocido: {name}")


def resolved(cfg: dict) -> dict:
    """'env:' solo se resuelve en campos secretos: en otros campos permitiría sacar el entorno por la URL."""
    return {k: db.resolve_secret(v) if k in db.SECRET_FIELDS else v for k, v in cfg.items()}


def dispatch(subject: str, text: str, payload: dict | None = None, only: str | None = None) -> list[dict]:
    results = []
    for name, cfg in db.channels().items():
        if (only and name != only) or (not only and not cfg.get("enabled")):
            continue
        try:
            send(name, cfg, subject, text, payload)
            results.append({"channel": name, "ok": True})
            db.log("info", f"Aviso enviado por {name}: {subject}")
        except Exception as e:  # un canal caído no bloquea al resto
            err = f"{type(e).__name__}: {e}"
            # p. ej. InvalidURL incluye la ruta /bot<token>/...; los valores cortos no se tapan (ilegible)
            for k, v in resolved(cfg).items():
                if k in db.SECRET_FIELDS and isinstance(v, str) and len(v) >= 6:
                    err = err.replace(v, "***")
            results.append({"channel": name, "ok": False, "error": "No se pudo enviar; consulta el registro."})
            db.log("error", f"Fallo enviando por {name}: {err}")
    return results
