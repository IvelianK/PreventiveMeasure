"""Canales de aviso: email, Telegram, WhatsApp (Twilio / CallMeBot), Discord, Slack, Teams, ntfy y webhook."""
import base64
import hashlib
import hmac
import json
import smtplib
import ssl
import string
import urllib.parse
import urllib.request
from email.message import EmailMessage

from . import db
from .sources import open_url

UA = {"User-Agent": "PreventiveMeasure/1.0"}


def render(template: str, ctx: dict) -> str:
    return string.Template(template).safe_substitute({k: "" if v is None else v for k, v in ctx.items()})


def _post(url: str, body: bytes, headers: dict, timeout: int = 20) -> None:
    # Destinos de LAN permitidos (ntfy, webhooks internos); metadatos cloud bloqueados siempre
    req = urllib.request.Request(url, data=body, headers={**UA, **headers}, method="POST")
    with open_url(req, timeout, allow_private=True) as r:
        r.read(1024)


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
                req = urllib.request.Request(f"https://api.callmebot.com/whatsapp.php?{q}", headers=UA)
                with open_url(req, 30) as r:
                    r.read(1024)
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
