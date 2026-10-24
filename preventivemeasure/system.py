"""Inventario del sistema operativo local (Windows, Linux, macOS, BSD). Solo stdlib.

Lo usan tanto el servidor (objetivo "system") como el agente remoto.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .manifests import comp, cpe_comp, norm_product, os_ecosystem

# Nombre visible -> (vendor, producto) CPE para el software de escritorio/servidor más común.
KNOWN = {
    r"google chrome": ("google", "chrome"), r"mozilla firefox": ("mozilla", "firefox"),
    r"microsoft edge$": ("microsoft", "edge_chromium"), r"7-zip": ("7-zip", "7-zip"),
    r"winrar": ("rarlab", "winrar"), r"notepad\+\+": ("notepad-plus-plus", "notepad++"),
    r"vlc media player": ("videolan", "vlc_media_player"), r"adobe acrobat reader": ("adobe", "acrobat_reader_dc"),
    r"zoom": ("zoom", "zoom"), r"openssl": ("openssl", "openssl"), r"python \d": ("python", "python"),
    r"node\.js": ("nodejs", "node.js"), r"git$|^git version": ("git-scm", "git"), r"putty": ("putty", "putty"),
    r"filezilla": ("filezilla-project", "filezilla_client"), r"wireshark": ("wireshark", "wireshark"),
    r"visual studio code": ("microsoft", "visual_studio_code"), r"oracle vm virtualbox": ("oracle", "vm_virtualbox"),
    r"docker desktop": ("docker", "desktop"), r"teamviewer": ("teamviewer", "teamviewer"),
    r"anydesk": ("anydesk", "anydesk"), r"java.*(runtime|update|\d)": ("oracle", "jre"),
    r"keepass": ("keepass", "keepass"), r"openvpn": ("openvpn", "openvpn"), r"winscp": ("winscp", "winscp"),
    r"mysql server": ("oracle", "mysql"), r"postgresql": ("postgresql", "postgresql"),
    r"microsoft office": ("microsoft", "office"), r"slack": ("slack", "slack"), r"telegram": ("telegram", "telegram_desktop"),
    r"forticlient": ("fortinet", "forticlient"), r"citrix workspace": ("citrix", "workspace"),
    r"vmware workstation": ("vmware", "workstation"), r"xampp": ("apachefriends", "xampp"),
}


def guess_cpe(name: str, publisher: str = "") -> tuple[str | None, str]:
    low = name.lower()
    for pat, (vendor, product) in KNOWN.items():
        if re.search(pat, low):
            return vendor, product
    # Heurística: nombre sin versión, arquitectura ni publisher
    base = re.sub(r"\(.*?\)|\b(x64|x86|64-bit|32-bit|amd64|version)\b|\d+(\.\d+)+", " ", low)
    for word in publisher.lower().replace(",", " ").split():
        if len(word) > 2 and word not in ("inc", "inc.", "ltd", "llc", "corporation", "corp"):
            base = base.replace(word, " ")
    vendor = norm_product(publisher.split(",")[0].split(" ")[0]) if publisher else None
    return vendor or None, norm_product(base) or norm_product(low)


def _exe(name: str) -> str | None:
    """Ruta absoluta y de confianza. En Windows shutil.which y CreateProcess miran antes el directorio actual:
    un git.exe plantado junto a data/ se ejecutaría con los privilegios del servicio."""
    exe = shutil.which(name)
    if not exe or not os.path.isabs(exe) or Path(exe).resolve().parent == Path.cwd().resolve():
        return None
    if sys.platform == "win32" and not exe.lower().endswith(".exe"):
        return None  # .bat/.cmd pasan por cmd.exe
    return exe


def _run(cmd: list[str], timeout: int = 60, with_stderr: bool = False) -> str:
    if not (exe := _exe(cmd[0])):
        return ""
    try:
        r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout, errors="replace",
                           cwd=Path(exe).parent, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout + r.stderr if with_stderr else r.stdout


def os_release() -> dict:
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(p).read_text()
        except OSError:
            continue
        return {k: v.strip('"') for k, v in re.findall(r"^(\w+)=(.*)$", text, re.M)}
    return {}


def windows() -> list[dict]:
    import winreg

    out = []
    roots = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                vals = {}
                for field in ("DisplayName", "DisplayVersion", "Publisher", "SystemComponent"):
                    try:
                        vals[field] = winreg.QueryValueEx(sub, field)[0]
                    except OSError:
                        pass
            except OSError:
                continue
            name, ver = vals.get("DisplayName"), vals.get("DisplayVersion")
            if name and ver and not vals.get("SystemComponent"):
                vendor, product = guess_cpe(name, vals.get("Publisher", ""))
                out.append(cpe_comp(product, str(ver), "registry", vendor, name))
    ver = platform.version()  # 10.0.26100
    release = "windows_11" if int(ver.split(".")[-1]) >= 22000 else f"windows_{platform.release().lower()}"
    out.append(cpe_comp(release, ver, "os", "microsoft", f"Windows {platform.release()}"))
    return out


def linux() -> list[dict]:
    rel = os_release()
    did, dver = rel.get("ID", ""), rel.get("VERSION_ID", "")
    eco = os_ecosystem(did, dver) or os_ecosystem(rel.get("ID_LIKE", "").split(" ")[0], dver)
    out = []
    dpkg = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${db:Status-Status}\n"])
    for line in dpkg.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[3] == "installed":
            # OSV indexa Debian/Ubuntu por paquete fuente
            name = parts[2] or parts[0]
            out.append(comp(eco, name, parts[1], "dpkg") if eco else cpe_comp(name, parts[1], "dpkg"))
    rpm = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n"])
    for line in rpm.splitlines():
        name, _, ver = line.partition("\t")
        ver = ver.removeprefix("(none):")
        out.append(comp(eco, name, ver, "rpm") if eco else cpe_comp(name, ver.split("-")[0], "rpm"))
    for line in _run(["apk", "info", "-v"]).splitlines():
        if m := re.match(r"^(.+)-(\d[^-]*-r\d+)$", line):
            out.append(comp(eco or "Alpine", m.group(1), m.group(2), "apk"))
    for line in _run(["pacman", "-Q"]).splitlines():
        name, _, ver = line.partition(" ")
        out.append(cpe_comp(name, ver.split("-")[0], "pacman"))
    for line in _run(["snap", "list"]).splitlines()[1:]:
        f = line.split()
        if len(f) >= 2:
            out.append(cpe_comp(f[0], f[1], "snap"))
    kernel = platform.release()
    out.append(comp("Linux", "Kernel", re.match(r"[\d.]+", kernel).group(0).rstrip("."), "kernel"))
    if did:
        out.append(cpe_comp(did, dver, "os", did, rel.get("PRETTY_NAME", did)))
    return out


def macos() -> list[dict]:
    out = [cpe_comp("macos", platform.mac_ver()[0], "os", "apple", "macOS")]
    try:
        apps = json.loads(_run(["system_profiler", "SPApplicationsDataType", "-json"], 180) or "{}")
    except json.JSONDecodeError:
        apps = {}
    for app in apps.get("SPApplicationsDataType", []):
        if app.get("version") and app.get("_name") and not app.get("path", "").startswith("/System/"):
            vendor, product = guess_cpe(app["_name"])
            out.append(cpe_comp(product, app["version"], "applications", vendor, app["_name"]))
    return out + homebrew()


def homebrew() -> list[dict]:
    out = []
    for line in _run(["brew", "list", "--versions"]).splitlines():
        f = line.split()
        if len(f) >= 2:
            out.append(cpe_comp(f[0], f[-1].split("_")[0], "homebrew"))
    return out


def runtimes() -> list[dict]:
    """Intérpretes y servidores en PATH (versión por línea de comandos)."""
    out = [cpe_comp("python", platform.python_version(), "runtime", "python", "Python (PreventiveMeasure)")]
    probes = {
        ("node", "--version"): ("nodejs", "node.js"), ("php", "-v"): ("php", "php"),
        ("nginx", "-v"): ("f5", "nginx"), ("httpd", "-v"): ("apache", "http_server"),
        ("apache2", "-v"): ("apache", "http_server"), ("openssl", "version"): ("openssl", "openssl"),
        ("java", "-version"): ("oracle", "jdk"), ("docker", "--version"): ("docker", "engine"),
        ("git", "--version"): ("git-scm", "git"), ("ssh", "-V"): ("openbsd", "openssh"),
        ("mysql", "--version"): ("oracle", "mysql"), ("psql", "--version"): ("postgresql", "postgresql"),
        ("redis-server", "--version"): ("redis", "redis"), ("sudo", "--version"): ("sudo_project", "sudo"),
        ("curl", "--version"): ("haxx", "curl"), ("bash", "--version"): ("gnu", "bash"),
        ("ruby", "--version"): ("ruby-lang", "ruby"), ("go", "version"): ("golang", "go"),
    }
    for (cmd, arg), (vendor, product) in probes.items():
        if m := re.search(r"(\d+\.\d+(?:\.\d+)?[a-z]?)", _run([cmd, arg], 15, with_stderr=True)):
            out.append(cpe_comp(product, m.group(1), "runtime", vendor, cmd))
    return out


def inventory() -> dict:
    match sys.platform:
        case "win32":
            items = windows()
        case "darwin":
            items = macos()
        case _:
            items = linux() + homebrew()
    return {"hostname": platform.node(), "os": f"{platform.system()} {platform.release()}",
            "components": items + runtimes()}
