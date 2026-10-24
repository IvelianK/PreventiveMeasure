"""CLI: servidor con panel, agente remoto y comprobación puntual para CI."""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request


def serve(args) -> None:
    import uvicorn

    from . import db

    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    env_token = os.environ.get("PM_ADMIN_TOKEN", "").strip()
    if env_token and len(env_token) < 32:
        if not loopback:
            sys.exit("PM_ADMIN_TOKEN debe tener al menos 32 caracteres si el panel escucha en red")
        print("Aviso: PM_ADMIN_TOKEN corto; aceptable solo en local.", file=sys.stderr)
    os.umask(0o077)  # BD, WAL y subidas solo legibles por el usuario del servicio
    os.environ["PM_BIND_HOST"] = args.host  # activa la validación de Host en loopback (api.py)
    new_token = db.init()
    print(f"PreventiveMeasure en http://{args.host}:{args.port}")
    if env_token:
        print("Token de administración: el de la variable PM_ADMIN_TOKEN")
    elif new_token:
        print(f"Token de administración (se muestra solo esta vez, guárdalo): {new_token}")
    else:
        print("Token de administración: el que guardaste. Si lo perdiste: preventivemeasure rotate-admin-token")
    if not loopback:
        print("AVISO: el panel queda expuesto en red. Ponlo detrás de un proxy con TLS y define PM_ALLOWED_HOSTS.",
              file=sys.stderr)
    uvicorn.run("preventivemeasure.api:app", host=args.host, port=args.port, log_level="warning")


def agent(args) -> None:
    from . import manifests, system

    token = args.token or os.environ.get("PM_AGENT_TOKEN", "")
    if not token:
        sys.exit("Falta el token de agente: --token o variable PM_AGENT_TOKEN")
    u = urllib.parse.urlsplit(args.server)
    if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        print("Aviso: servidor sin https; el token viaja en claro por la red.", file=sys.stderr)
    while True:
        inv = system.inventory()
        for path in args.path or []:
            comps, errors = manifests.scan_path(path)
            inv["components"] += comps
            for e in errors:
                print(f"aviso: {e}", file=sys.stderr)
        inv["components"] = manifests.dedupe(inv["components"])
        req = urllib.request.Request(
            args.server.rstrip("/") + "/api/agent/ingest", data=json.dumps(inv).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (servidor indicado por el usuario)
                print(f"{time.strftime('%H:%M:%S')} enviado: {r.read().decode()}")
        except Exception as e:
            print(f"{time.strftime('%H:%M:%S')} error enviando inventario: {e}", file=sys.stderr)
        if not args.every:
            return
        time.sleep(args.every * 60)


def check(args) -> int:
    """Escaneo sin servidor contra OSV. Código de salida 1 si hay vulnerabilidades >= --fail-on."""
    from . import cvss, manifests, sources

    comps, errors = manifests.scan_path(args.path)
    pkgs = [c for c in comps if c["ecosystem"] != "CPE" and c["version"]]
    for e in errors:
        print(f"aviso: {e}", file=sys.stderr)
    hits = sources.osv_batch([{"package": {"ecosystem": c["ecosystem"], "name": c["name"]}, "version": c["version"]}
                              for c in pkgs]) if pkgs else []
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    worst, rows, cache = -1, [], {}
    for comp, row in zip(pkgs, hits):
        for vid, _ in row:
            v = cache.get(vid) or cache.setdefault(vid, sources.osv_vuln(vid))
            p = sources.parse_osv(v)
            sev = p["severity"] if p["severity"] in order else cvss.label(p["cvss"])
            fixed = sources.osv_fixed(v, comp["ecosystem"], comp["name"], comp["version"]) or "sin parche"
            rows.append((sev, comp["ecosystem"], comp["name"], comp["version"], vid, fixed, p["summary"][:80]))
            worst = max(worst, order.index(sev) if sev in order else 1)
    rows.sort(key=lambda r: -(order.index(r[0]) if r[0] in order else 1))
    print(f"{len(comps)} componentes, {len(pkgs)} consultables en OSV, {len(rows)} vulnerabilidades\n")
    for r in rows:
        print(f"[{r[0]:<8}] {r[1]}:{r[2]}@{r[3]}  {r[4]}  -> corregida en {r[5]}\n           {r[6]}")
    return 1 if rows and worst >= order.index(args.fail_on.upper()) else 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="preventivemeasure", description="Monitor de vulnerabilidades de tu stack")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="Servidor con panel web y sondeo periódico")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    a = sub.add_parser("agent", help="Inventaria esta máquina y lo envía a un servidor")
    a.add_argument("--server", required=True)
    a.add_argument("--token", help="Token de agente (Ajustes > Agentes). Mejor PM_AGENT_TOKEN: argv se ve en ps")
    a.add_argument("--path", action="append", help="Proyecto a incluir (repetible)")
    a.add_argument("--every", type=int, default=0, help="Repetir cada N minutos (0 = una vez)")
    c = sub.add_parser("check", help="Comprobación puntual de un proyecto (CI)")
    c.add_argument("path")
    c.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    sub.add_parser("token", help="Muestra el token de agente")
    sub.add_parser("rotate-admin-token", help="Genera un token de administración nuevo (invalida el anterior)")
    args = ap.parse_args()
    match args.cmd:
        case "serve":
            serve(args)
        case "agent":
            agent(args)
        case "check":
            sys.exit(check(args))
        case "token" | "rotate-admin-token":
            from . import db

            new_token = db.init()
            if args.cmd == "rotate-admin-token":
                new_token = db.rotate_admin_token()
            if new_token:
                print(f"admin (solo se muestra ahora): {new_token}")
            print(f"agente: {db.get_setting('agent_token')}")


if __name__ == "__main__":
    main()
