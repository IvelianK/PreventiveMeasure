"""Priorización y recomendaciones accionables por hallazgo."""

PRIORITIES = ["low", "medium", "high", "critical"]

# CWE -> mitigación temporal mientras no se pueda parchear
CWE_MITIGATIONS = {
    "CWE-79": "XSS: escapa la salida, activa una Content-Security-Policy estricta (sin 'unsafe-inline') y filtra la entrada en el WAF.",
    "CWE-89": "Inyección SQL: usa consultas parametrizadas, reduce privilegios de la cuenta de BD y activa reglas SQLi en el WAF.",
    "CWE-78": "Inyección de comandos: bloquea en el WAF los parámetros afectados, desactiva funciones de ejecución (p. ej. exec/system en PHP: disable_functions) y ejecuta el servicio sin privilegios.",
    "CWE-77": "Inyección de comandos: valida contra lista blanca, evita la shell y limita el usuario del proceso.",
    "CWE-94": "Ejecución de código: restringe el acceso a la funcionalidad vulnerable (IP/autenticación), bloquea patrones en el WAF y vigila procesos hijos inesperados.",
    "CWE-95": "Eval injection: elimina el uso de eval con datos externos y filtra la entrada en el WAF.",
    "CWE-22": "Path traversal: normaliza rutas, bloquea '../' y codificaciones en el WAF y monta el contenido en solo lectura.",
    "CWE-434": "Subida de ficheros: limita extensiones y tipos MIME, guarda fuera del webroot y desactiva la ejecución en el directorio de subidas.",
    "CWE-502": "Deserialización insegura: no deserialices datos no confiables, aplica listas blancas de clases y aísla el servicio.",
    "CWE-918": "SSRF: bloquea en la salida rangos internos y el endpoint de metadatos (169.254.169.254) y usa lista blanca de destinos.",
    "CWE-287": "Autenticación rota: pon el servicio detrás de VPN/SSO, fuerza MFA y revisa accesos recientes.",
    "CWE-306": "Falta de autenticación: no expongas el servicio a Internet; restringe por IP o VPN hasta parchear.",
    "CWE-862": "Falta de autorización: restringe el endpoint afectado y revisa los registros de acceso.",
    "CWE-863": "Autorización incorrecta: limita el acceso a la funcionalidad afectada y audita permisos.",
    "CWE-352": "CSRF: exige tokens anti-CSRF y cookies SameSite=Strict.",
    "CWE-611": "XXE: desactiva entidades externas y DTD en el parser XML.",
    "CWE-787": "Corrupción de memoria: aísla el proceso, activa ASLR/DEP y restringe la entrada no confiable hasta parchear.",
    "CWE-416": "Use-after-free: actualiza cuanto antes; mientras, evita abrir contenido no confiable con el componente.",
    "CWE-120": "Desbordamiento de búfer: limita la exposición del servicio y la entrada no confiable.",
    "CWE-400": "Consumo de recursos (DoS): aplica rate limiting y límites de tamaño en el proxy inverso.",
    "CWE-770": "Asignación sin límites: configura límites de memoria/conexiones y rate limiting.",
    "CWE-200": "Exposición de información: revisa qué se expone, rota secretos que pudieran haberse filtrado.",
    "CWE-798": "Credenciales embebidas: rota las credenciales afectadas y muévelas a un gestor de secretos.",
    "CWE-601": "Open redirect: valida destinos de redirección contra lista blanca.",
    "CWE-1321": "Prototype pollution: congela Object.prototype o valida claves (__proto__, constructor) en la entrada JSON.",
    "CWE-269": "Escalada de privilegios: limita cuentas locales y aplica mínimo privilegio.",
    "CWE-427": "Carga de librerías no confiables: revisa permisos de los directorios del PATH de búsqueda.",
}


def priority(cvss: float | None, kev: bool, epss: float | None, confidence: str) -> str:
    if kev:
        return "critical"
    score = 5.0 if cvss is None else cvss
    if epss is not None and epss >= 0.3 and score >= 7:
        return "critical"
    level = next(p for limit, p in ((9, "critical"), (7, "high"), (4, "medium"), (0, "low")) if score >= limit)
    if confidence == "possible" and level == "critical":
        return "high"  # sin versión confirmada no se grita "crítico"
    return level


def rank(p: str | None) -> int:
    return PRIORITIES.index(p) if p in PRIORITIES else -1


def recommendation(comp: dict, vuln: dict, fixed: str | None, kev: dict | None, epss: float | None,
                   confidence: str) -> dict:
    steps = []
    name, version = comp["name"], comp["version"] or "?"
    if fixed:
        if fixed.startswith(">"):
            steps.append(f"Actualiza {name} a una versión posterior a {fixed[1:].strip()} (tienes {version}).")
        else:
            steps.append(f"Actualiza {name} de {version} a {fixed} o superior.")
            steps.append(_upgrade_cmd(comp, fixed))
    else:
        steps.append(f"No hay versión corregida publicada para {name}. Aplica las mitigaciones temporales y vigila el aviso del fabricante.")
    if kev:
        steps.insert(0, f"CISA confirma explotación activa. Acción requerida: {kev.get('action') or 'aplicar parches del fabricante'}"
                        + (f" (fecha límite federal {kev['due']})." if kev.get("due") else "."))
        if (kev.get("ransomware") or "").lower() == "known":
            steps.insert(1, "Usada en campañas de ransomware: verifica copias de seguridad offline y busca indicadores de compromiso.")
    elif epss is not None and epss >= 0.1:
        steps.append(f"Probabilidad de explotación en 30 días (EPSS): {epss:.0%}. Trátala como urgente.")
    for cwe in vuln.get("cwes", []):
        if tip := CWE_MITIGATIONS.get(cwe):
            steps.append(f"Mitigación temporal ({cwe}): {tip}")
    if confidence == "possible":
        steps.insert(0, "Coincidencia por nombre en un aviso aún sin analizar: confirma si tu versión está afectada leyendo el aviso.")
    elif confidence == "probable":
        steps.insert(0, "Rango de versiones declarado por el fabricante (CNA); NVD aún no lo ha verificado.")
    if comp.get("source", "").startswith(("http://", "https://")):
        steps.append("Componente expuesto en web: oculta cabeceras de versión (Server, X-Powered-By) para reducir el reconocimiento automatizado.")
    steps = [s for s in steps if s]
    return {"steps": steps, "fixed": fixed, "links": vuln.get("refs", [])[:6]}


def _upgrade_cmd(comp: dict, fixed: str) -> str:
    n = comp["name"]
    match comp["ecosystem"]:
        case "npm":
            return f"Comando: npm install {n}@^{fixed}  (o yarn up {n}@^{fixed})"
        case "PyPI":
            return f"Comando: pip install --upgrade \"{n}>={fixed}\"  y actualiza el lockfile"
        case "Packagist":
            return f"Comando: composer require {n}:^{fixed}"
        case "RubyGems":
            return f"Comando: bundle update {n}  (Gemfile: '>= {fixed}')"
        case "Go":
            return f"Comando: go get {n}@v{fixed} && go mod tidy" if n != "stdlib" else f"Actualiza la toolchain de Go a {fixed}."
        case "crates.io":
            return f"Comando: cargo update -p {n} --precise {fixed}"
        case "Maven":
            return f"Cambia la versión de {n} a {fixed} en pom.xml / build.gradle y recompila."
        case "NuGet":
            return f"Comando: dotnet add package {n} --version {fixed}"
        case "Pub":
            return f"Comando: flutter pub upgrade {n}  (pubspec: ^{fixed})"
        case "Hex":
            return f"Comando: mix deps.update {n}"
        case e if e.startswith(("Debian", "Ubuntu")):
            return f"Comando: sudo apt update && sudo apt install --only-upgrade {n}"
        case e if e.startswith("Alpine"):
            return f"Comando: apk upgrade {n}"
        case e if e.startswith(("Rocky", "AlmaLinux", "Red Hat")):
            return f"Comando: sudo dnf upgrade {n}"
    return ""
