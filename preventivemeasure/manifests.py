"""Detección de dependencias en proyectos, SBOM y binarios móviles. Solo stdlib.

Cada detector devuelve componentes como dicts:
  {"ecosystem", "name", "version", "source", "vendor"?, "product"?}
ecosystem = nombre OSV (npm, PyPI, Maven...) o "CPE" (se cruza con NVD por producto).
"""
import json
import os
import plistlib
import re
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "venv", ".venv", "env", "__pycache__", ".tox", "dist",
             "build", "target", ".gradle", ".idea", "Pods", "DerivedData", ".next", ".nuxt", "vendor", ".dart_tool"}
MAX_FILES = 20000
MAX_WALK = 500_000                       # entradas recorridas (no solo ficheros reconocidos)
MAX_TEXT, MAX_SBOM = 50 << 20, 100 << 20  # bytes por manifiesto / SBOM
MAX_ZIP_ENTRIES, MAX_ZIP_MEMBER = 200_000, 1 << 20


def comp(eco: str, name: str, version: str, source: str, vendor: str | None = None, product: str | None = None) -> dict:
    return {"ecosystem": eco, "name": name.strip(), "version": (version or "").strip(), "source": source,
            "vendor": vendor, "product": product}


def cpe_comp(product: str, version: str, source: str, vendor: str | None = None, name: str | None = None) -> dict:
    return comp("CPE", name or product, version, source, vendor, norm_product(product))


def norm_product(s: str) -> str:
    return re.sub(r"[^a-z0-9.+_-]+", "_", s.lower()).strip("_")


def safe_xml(data: str | bytes) -> ET.Element:
    """Rechaza DTD con subconjunto interno o entidades en el prólogo (billion laughs).

    Solo se mira antes del elemento raíz: un artículo sobre XXE con '<!ENTITY' en CDATA es legítimo."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    root = re.search(r"<[A-Za-z_]", text)
    prologue = text[: root.start() if root else len(text)]
    if "<!ENTITY" in prologue.upper() or re.search(r"<!DOCTYPE[^>\[]{0,500}\[", prologue, re.I):
        raise ValueError("XML con DTD interna o entidades rechazado")
    return ET.fromstring(data)


def _clean_ver(v: str) -> str:
    """'^1.2.3' -> '1.2.3'; rangos abiertos o vacíos -> ''."""
    v = (v or "").strip().strip("'\"")
    m = re.match(r"^(?:[=v^~]|==|>=)?\s*(\d[\w.\-+]*)$", v)
    return m.group(1) if m else ""


# --- npm -------------------------------------------------------------------

def npm_lock(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for key, meta in (data.get("packages") or {}).items():
        if key and "node_modules/" in key and meta.get("version") and not meta.get("link"):
            out.append(comp("npm", key.rsplit("node_modules/", 1)[1], meta["version"], str(p)))
    if not out:  # lockfileVersion 1

        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    out.append(comp("npm", name, meta["version"], str(p)))
                walk(meta.get("dependencies"))

        walk(data.get("dependencies"))
    return out


def yarn_lock(p: Path, text: str) -> list[dict]:
    out = []
    for block in re.split(r"\n(?=\S)", text):
        head = block.split("\n", 1)[0].strip().rstrip(":").strip('"')
        m = re.search(r'^[ \t]+version:?[ \t]+"?([^"\s]+)', block, re.M)  # sin \s+ anidados: lineal
        if not m or head.startswith("#") or head.startswith("__metadata"):
            continue
        first = head.split(",")[0].strip().strip('"')
        name = first[: first.rfind("@")] if first.rfind("@") > 0 else first
        out.append(comp("npm", name, m.group(1), str(p)))
    return out


def pnpm_lock(p: Path, text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s{2}'?/?((?:@[^/@\s]+/)?[^@\s/']+)[@/](\d[^:('\s]*)", text, re.M):
        out.append(comp("npm", m.group(1), m.group(2), str(p)))
    return out


def package_json(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and (v := _clean_ver(spec)):
                out.append(comp("npm", name, v, str(p)))
    if (engines := data.get("engines") or {}).get("node") and (v := _clean_ver(engines["node"])):
        out.append(cpe_comp("node.js", v, str(p), "nodejs", "node"))
    return out


# --- Python ----------------------------------------------------------------

def requirements(p: Path, text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([\w.\-+!]+)", line)
        if m:
            out.append(comp("PyPI", m.group(1), m.group(2), str(p)))
    return out


def toml_lock(eco: str):
    def parse(p: Path, text: str) -> list[dict]:
        return [comp(eco, pk["name"], pk.get("version", ""), str(p))
                for pk in tomllib.loads(text).get("package", []) if pk.get("version")]
    return parse


def pipfile_lock(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    return [comp("PyPI", n, m["version"].lstrip("="), str(p))
            for sec in ("default", "develop") for n, m in (data.get(sec) or {}).items() if m.get("version")]


# --- PHP / Ruby / Go / Rust / Elixir / Dart --------------------------------

def composer_lock(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    out = [comp("Packagist", pk["name"], pk["version"].lstrip("v"), str(p))
           for sec in ("packages", "packages-dev") for pk in data.get(sec) or [] if pk.get("version")]
    if (php := (data.get("platform") or {}).get("php")) and (v := _clean_ver(php)):
        out.append(cpe_comp("php", v, str(p), "php"))
    return out


def gemfile_lock(p: Path, text: str) -> list[dict]:
    return [comp("RubyGems", m.group(1), m.group(2), str(p))
            for m in re.finditer(r"^ {4}([A-Za-z0-9_.\-]+) \(([\w.\-]+)\)$", text, re.M)]


def go_mod(p: Path, text: str) -> list[dict]:
    out = [comp("Go", m.group(1), m.group(2).lstrip("v"), str(p))
           for m in re.finditer(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+(v[\w.\-+]+)", text, re.M)]
    if m := re.search(r"^go (\d[\d.]*)", text, re.M):
        out.append(comp("Go", "stdlib", m.group(1), str(p)))
    return out


def mix_lock(p: Path, text: str) -> list[dict]:
    return [comp("Hex", m.group(1), m.group(2), str(p))
            for m in re.finditer(r'"([\w\-]+)":\s*\{:hex,\s*:[\w\-]+,\s*"([\w.\-]+)"', text)]


def pubspec_lock(p: Path, text: str) -> list[dict]:
    return [comp("Pub", m.group(1), m.group(2), str(p))
            for m in re.finditer(r'^  ([\w\-]+):\n(?:    .*\n)*?    version: "([^"]+)"', text, re.M)]


# --- JVM / Android ---------------------------------------------------------

def pom_xml(p: Path, text: str) -> list[dict]:
    root = safe_xml(text)
    for el in root.iter():  # quita el namespace Maven de las etiquetas
        el.tag = el.tag.rsplit("}", 1)[-1]
    props = {e.tag: (e.text or "").strip() for e in root.findall("./properties/*")}
    if (pv := root.findtext("./version")) is not None:
        props["project.version"] = pv.strip()
    out = []
    for dep in root.iter("dependency"):
        g, a, v = (dep.findtext(x, "").strip() for x in ("groupId", "artifactId", "version"))
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
        if g and a and v and "${" not in v:
            out.append(comp("Maven", f"{g}:{a}", v, str(p)))
    return out


_GRADLE = re.compile(r"""['"]([\w.\-]+):([\w.\-]+):(\d[\w.\-]*)['"]""")


def gradle(p: Path, text: str) -> list[dict]:
    return [comp("Maven", f"{g}:{a}", v, str(p)) for g, a, v in _GRADLE.findall(text)]


def gradle_catalog(p: Path, text: str) -> list[dict]:
    data = tomllib.loads(text)
    versions = data.get("versions", {})
    out = []
    for lib in data.get("libraries", {}).values():
        if isinstance(lib, str):
            parts = lib.split(":")
            if len(parts) == 3:
                out.append(comp("Maven", f"{parts[0]}:{parts[1]}", parts[2], str(p)))
            continue
        module = lib.get("module") or (f"{lib['group']}:{lib['name']}" if "group" in lib else None)
        ver = lib.get("version")
        if isinstance(ver, dict):
            ver = versions.get(ver.get("ref"), "") if "ref" in ver else ver.get("strictly") or ver.get("require")
        if module and isinstance(ver, str) and ver:
            out.append(comp("Maven", module, ver, str(p)))
    return out


# --- .NET ------------------------------------------------------------------

def nuget_lock(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    return [comp("NuGet", n, m["resolved"], str(p))
            for fw in (data.get("dependencies") or {}).values() for n, m in fw.items() if m.get("resolved")]


def csproj(p: Path, text: str) -> list[dict]:
    out = []
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text, re.I):
        if v := _clean_ver(m.group(2)):
            out.append(comp("NuGet", m.group(1), v, str(p)))
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text, re.I):
        out.append(comp("NuGet", m.group(1), m.group(2), str(p)))
    return out


# --- Apple -----------------------------------------------------------------

def podfile_lock(p: Path, text: str) -> list[dict]:
    # ponytail: OSV no indexa CocoaPods; se cruza con NVD por nombre de producto
    pods = text.split("\nDEPENDENCIES:", 1)[0]
    return [cpe_comp(m.group(1).split("/")[0], m.group(2), str(p))
            for m in re.finditer(r"^  - ([\w\-/+]+) \(([\w.\-]+)\)", pods, re.M)]


def package_resolved(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    out = []
    for pin in pins:
        url = pin.get("location") or pin.get("repositoryURL") or ""
        ver = (pin.get("state") or {}).get("version")
        if url and ver:
            out.append(comp("SwiftURL", re.sub(r"^https?://|\.git$", "", url), ver, str(p)))
    return out


# --- Contenedores ----------------------------------------------------------

DOCKER_IMAGES = {  # imagen oficial -> (vendor, producto CPE)
    "php": ("php", "php"), "nginx": ("f5", "nginx"), "httpd": ("apache", "http_server"),
    "node": ("nodejs", "node.js"), "python": ("python", "python"), "postgres": ("postgresql", "postgresql"),
    "mysql": ("oracle", "mysql"), "mariadb": ("mariadb", "mariadb"), "redis": ("redis", "redis"),
    "tomcat": ("apache", "tomcat"), "mongo": ("mongodb", "mongodb"), "wordpress": ("wordpress", "wordpress"),
    "traefik": ("traefik", "traefik"), "haproxy": ("haproxy", "haproxy"), "elasticsearch": ("elastic", "elasticsearch"),
    "rabbitmq": ("vmware", "rabbitmq"), "golang": ("golang", "go"), "ruby": ("ruby-lang", "ruby"),
    "openjdk": ("oracle", "openjdk"), "eclipse-temurin": ("eclipse", "temurin"), "caddy": ("caddyserver", "caddy"),
    "grafana/grafana": ("grafana", "grafana"), "gitlab/gitlab-ce": ("gitlab", "gitlab"), "jenkins/jenkins": ("jenkins", "jenkins"),
}


def dockerfile(p: Path, text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s*(?:FROM|image:)\s+(?:--platform=\S+\s+)?\"?([\w.\-/]+):v?(\d[\w.\-]*)", text, re.M | re.I):
        img, tag = m.group(1).lower().removeprefix("library/").removeprefix("docker.io/"), m.group(2)
        if hit := DOCKER_IMAGES.get(img):
            out.append(cpe_comp(hit[1], re.match(r"[\d.]+", tag).group(0).rstrip("."), str(p), hit[0], img))
    return out


# --- SBOM ------------------------------------------------------------------

PURL_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "gem": "RubyGems", "golang": "Go", "cargo": "crates.io",
            "nuget": "NuGet", "composer": "Packagist", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL",
            "cocoapods": "CPE", "conan": "ConanCenter", "cran": "CRAN", "hackage": "Hackage"}


def from_purl(purl: str, source: str) -> dict | None:
    m = re.match(r"^pkg:([a-z]+)/(.+?)@([^?#]+)(?:\?([^#]*))?", purl)
    if not m:
        return None
    ptype, path, version, qs = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    path = re.sub(r"%40", "@", path)
    quals = dict(q.split("=", 1) for q in qs.split("&") if "=" in q)
    if ptype in ("deb", "apk", "rpm"):
        distro = quals.get("distro", "")
        name = path.split("/")[-1]
        eco = os_ecosystem(path.split("/")[0], re.sub(r"^\D+-?", "", distro)) if distro else None
        return comp(eco, name, version, source) if eco else cpe_comp(name, version, source)
    eco = PURL_ECO.get(ptype)
    if not eco:
        return cpe_comp(path.split("/")[-1], version, source)
    name = path.replace("/", ":", 1) if ptype == "maven" else path
    return cpe_comp(name, version, source) if eco == "CPE" else comp(eco, name, version, source)


def sbom(p: Path, text: str) -> list[dict]:
    data = json.loads(text)
    out = []
    if "components" in data:  # CycloneDX (anidados incluidos)
        stack = list(data["components"])
        while stack:
            c = stack.pop()
            stack.extend(c.get("components") or [])
            if c.get("purl") and (x := from_purl(c["purl"], str(p))):
                out.append(x)
            elif c.get("cpe"):
                cpe = c["cpe"].split(":")
                if len(cpe) > 5:
                    out.append(cpe_comp(cpe[4], c.get("version") or cpe[5], str(p), cpe[3]))
    for pk in data.get("packages") or []:  # SPDX
        for ref in pk.get("externalRefs") or []:
            if ref.get("referenceType") == "purl" and (x := from_purl(ref["referenceLocator"], str(p))):
                out.append(x)
    return out


def os_ecosystem(distro_id: str, version: str) -> str | None:
    """Nombre de ecosistema OSV para paquetes del sistema operativo."""
    major = version.split(".")[0]
    match distro_id.lower():
        case "debian":
            return f"Debian:{major}" if major else "Debian"
        case "ubuntu":
            lts = version.endswith(".04") and int(major or 1) % 2 == 0
            return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
        case "alpine":
            return "Alpine:v" + ".".join(version.split(".")[:2])
        case "rocky":
            return f"Rocky Linux:{major}"
        case "almalinux":
            return f"AlmaLinux:{major}"
        case "opensuse-leap" | "opensuse":
            return f"openSUSE:Leap {version}"
        case "sles":
            return f"SUSE:Linux Enterprise Server {major}"
    return None


# --- Binarios móviles ------------------------------------------------------

def _zip_members(z: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError(f"Archivo con más de {MAX_ZIP_ENTRIES} entradas")
    return infos


def apk_archive(p: Path) -> list[dict]:
    """APK/AAB: las librerías AndroidX/Jetpack dejan META-INF/<grupo>_<artefacto>.version."""
    out = []
    with zipfile.ZipFile(p) as z:
        for info in _zip_members(z):
            n = info.filename
            m = re.match(r"^(?:base/root/)?META-INF/([\w.\-]+)_([\w.\-]+)\.version$", n)
            if m:
                with z.open(info) as f:  # lee 64 bytes, no descomprime el miembro entero (zip bomb)
                    ver = f.read(64).decode("utf-8", "ignore").strip()
                if re.match(r"^\d", ver):
                    out.append(comp("Maven", f"{m.group(1)}:{m.group(2)}", ver, str(p)))
            elif re.match(r"^(?:base/)?lib/[^/]+/lib(\w+)\.so$", n):
                lib = re.match(r"^.*lib(\w+)\.so$", n).group(1)
                if lib in ("ssl", "crypto", "sqlite", "curl", "flutter", "reactnativejni", "hermes"):
                    out.append(cpe_comp(lib, "", str(p)))  # sin versión: solo inventario
    return out


def ipa_archive(p: Path) -> list[dict]:
    out = []
    with zipfile.ZipFile(p) as z:
        for member in _zip_members(z):
            n = member.filename
            if member.file_size <= MAX_ZIP_MEMBER and re.match(r"^Payload/[^/]+\.app/Frameworks/[^/]+\.framework/Info\.plist$", n):
                try:
                    with z.open(member) as f:
                        info = plistlib.loads(f.read(MAX_ZIP_MEMBER))
                except Exception:
                    continue
                name = info.get("CFBundleName") or n.split("/")[-2].removesuffix(".framework")
                if ver := info.get("CFBundleShortVersionString"):
                    out.append(cpe_comp(name, str(ver), str(p)))
    return out


# --- Despacho --------------------------------------------------------------

PARSERS = {
    "package-lock.json": npm_lock, "npm-shrinkwrap.json": npm_lock, "yarn.lock": yarn_lock,
    "pnpm-lock.yaml": pnpm_lock, "poetry.lock": toml_lock("PyPI"), "uv.lock": toml_lock("PyPI"),
    "pdm.lock": toml_lock("PyPI"), "Pipfile.lock": pipfile_lock, "Cargo.lock": toml_lock("crates.io"),
    "composer.lock": composer_lock, "Gemfile.lock": gemfile_lock, "go.mod": go_mod, "mix.lock": mix_lock,
    "pubspec.lock": pubspec_lock, "pom.xml": pom_xml, "build.gradle": gradle, "build.gradle.kts": gradle,
    "libs.versions.toml": gradle_catalog, "packages.lock.json": nuget_lock, "packages.config": csproj,
    "Podfile.lock": podfile_lock, "Package.resolved": package_resolved, "Dockerfile": dockerfile,
    "docker-compose.yml": dockerfile, "docker-compose.yaml": dockerfile, "compose.yml": dockerfile,
    "compose.yaml": dockerfile,
}
LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}


def parser_for(name: str):
    if name in PARSERS:
        return PARSERS[name]
    if re.match(r"^requirements.*\.txt$", name):
        return requirements
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return csproj
    if name.endswith((".cdx.json", ".spdx.json")) or name in ("bom.json", "sbom.json"):
        return sbom
    if name.startswith("Dockerfile"):
        return dockerfile
    return None


def scan_file(p: Path) -> list[dict]:
    if p.suffix.lower() in (".apk", ".aab"):
        return apk_archive(p)
    if p.suffix.lower() == ".ipa":
        return ipa_archive(p)
    parse = parser_for(p.name)
    if parse is None and p.suffix == ".json":
        parse = sbom  # subida manual de un SBOM con nombre libre
    if parse is None:
        return []
    return parse(p, _read_text(p, MAX_SBOM if parse is sbom else MAX_TEXT))


def _read_text(p: Path, limit: int = MAX_TEXT) -> str:
    if p.stat().st_size > limit:
        raise ValueError(f"Fichero mayor de {limit >> 20} MB, no analizado")
    return p.read_text(encoding="utf-8", errors="replace")


def path_allowed(path: str) -> bool:
    """PM_SCAN_ROOTS (separado por os.pathsep) acota qué rutas del servidor se pueden escanear. Vacío = sin límite."""
    roots = [r for r in os.environ.get("PM_SCAN_ROOTS", "").split(os.pathsep) if r.strip()]
    if not roots:
        return True
    norm = lambda p: Path(os.path.normcase(os.path.realpath(p)))  # Windows: sin distinguir mayúsculas
    return any(norm(path).is_relative_to(norm(r)) for r in roots)


def _wanted(name: str) -> bool:
    return bool(parser_for(name)) or name == "package.json" or name.lower().endswith((".apk", ".aab", ".ipa"))


def scan_path(root: str) -> tuple[list[dict], list[str]]:
    """Recorre un proyecto. Devuelve (componentes, errores); con errores el inventario se trata como parcial."""
    base = Path(root)
    out, errors, files = [], [], []
    if base.is_file():
        files = [base]
    elif not base.is_dir():
        errors.append(f"{root}: la ruta no existe o no es accesible")
    else:
        walked = 0
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]  # poda: no entra en node_modules & co.
            walked += len(dirnames) + len(filenames)
            files += [Path(dirpath, f) for f in filenames if _wanted(f)]
            if walked >= MAX_WALK or len(files) >= MAX_FILES:
                errors.append(f"Recorrido truncado ({walked} entradas, {len(files)} manifiestos): acota la ruta")
                break
    has_lock = {f.parent for f in files if f.name in LOCKS}
    for f in files:
        try:
            if f.name != "package.json":
                out.extend(scan_file(f))
            elif f.parent not in has_lock:  # package.json solo si no hay lockfile al lado
                out.extend(package_json(f, _read_text(f)))
        except Exception as e:  # un fichero roto no tumba el escaneo
            errors.append(f"{f}: {type(e).__name__}: {e}")
    return dedupe(out), errors


def dedupe(items: list[dict]) -> list[dict]:
    seen = {}
    for c in items:
        if c["name"]:
            seen[(c["ecosystem"], c["name"], c["version"], c["source"])] = c
    return list(seen.values())
