# PreventiveMeasure

Monitor de vulnerabilidades multiplataforma. Detecta qué software usas (webs, proyectos de código, apps móviles, equipos Windows/Linux/macOS, servidores remotos), lo cruza cada 30 minutos con las bases de vulnerabilidades y las noticias de ciberseguridad, y te avisa por email, Telegram, WhatsApp, Discord, Slack, Teams, ntfy o webhook con la acción concreta que debes tomar.

El proyecto incluye un inventario de prueba con dependencias antiguas para comprobar los detectores. Los resultados dependen de las fuentes externas y de la calidad de las versiones inventariadas.

## Qué detecta

| Origen | Cómo |
|---|---|
| Web / app web | Cabeceras (`Server`, `X-Powered-By`...), cookies, `meta generator`, plugins y temas de WordPress, librerías JS por URL de CDN, `?ver=` o banner de licencia |
| Proyectos | npm, yarn, pnpm, pip, Poetry, uv, PDM, Pipfile, Composer, Bundler, Go, Cargo, Maven, Gradle (y version catalogs), NuGet, Pub (Flutter), CocoaPods, SwiftPM, Hex, Dockerfile y docker-compose |
| SBOM | CycloneDX y SPDX JSON (cualquier ecosistema vía purl) |
| Apps móviles | APK/AAB (versiones de AndroidX/Jetpack embebidas) e IPA (frameworks embebidos) |
| Equipo local | Programas instalados (registro de Windows), dpkg, rpm, apk, pacman, snap, aplicaciones y Homebrew en macOS, kernel y runtimes en PATH |
| Servidores remotos | Agente sin dependencias (`python -m preventivemeasure agent`) que envía el inventario |
| Manual | Componentes añadidos a mano (firmware, NAS, routers...) |

## Fuentes de inteligencia

- **OSV.dev**: paquetes de todos los ecosistemas y distribuciones Linux (GitHub Advisories, PyPA, RustSec, Go, Debian, Ubuntu, Alpine...).
- **NVD (NIST)**: software identificado por CPE. Histórico por producto y, en cada ciclo, las CVE publicadas o modificadas desde el último sondeo. Si NVD aún no ha analizado una CVE, usa el rango de versiones declarado por el fabricante (CNA) y, en último caso, la mención del producto en la descripción.
- **CISA KEV**: explotación activa confirmada y acción requerida.
- **FIRST EPSS**: probabilidad de explotación en 30 días.
- **Feeds RSS** (CISA, The Hacker News, BleepingComputer, SANS ISC, configurables): aviso temprano, a menudo antes de que exista CVE.

La prioridad combina CVSS, KEV, EPSS y la confianza del cruce. Cada hallazgo trae: versión corregida más cercana, comando de actualización según el ecosistema, acción de CISA, mitigaciones temporales por tipo de debilidad (CWE) y referencias.

## Instalación

Requiere Python 3.11 o superior. Si ya tienes [pipx](https://pipx.pypa.io), instala la versión publicada en un solo comando:

```bash
pipx install https://github.com/IvelianK/PreventiveMeasure/releases/download/v1.0.1/preventivemeasure-1.0.1-py3-none-any.whl
```

Sin pipx, crea un entorno virtual. En **Windows PowerShell** (`py` es el lanzador de Python):

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install https://github.com/IvelianK/PreventiveMeasure/releases/download/v1.0.1/preventivemeasure-1.0.1-py3-none-any.whl
.\.venv\Scripts\preventivemeasure.exe serve
```

En **Linux o macOS**:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install https://github.com/IvelianK/PreventiveMeasure/releases/download/v1.0.1/preventivemeasure-1.0.1-py3-none-any.whl
.venv/bin/preventivemeasure serve
```

Esos comandos arrancan el panel. Abre <http://127.0.0.1:8765> y usa el token mostrado en el primer arranque. Guarda el token en un gestor de contraseñas. Los datos se crean en `./data` del directorio desde el que ejecutes el comando.

Para instalar desde el código, clona el repositorio y, dentro de su carpeta, sustituye la URL del wheel de los comandos anteriores por `.`:

```bash
git clone https://github.com/IvelianK/PreventiveMeasure.git
cd PreventiveMeasure
```

Cada release lleva una atestación de procedencia de GitHub. Para comprobar el wheel descargado necesitas [GitHub CLI](https://cli.github.com):

```bash
gh release download v1.0.1 -R IvelianK/PreventiveMeasure -p 'preventivemeasure-1.0.1-py3-none-any.whl'
gh attestation verify preventivemeasure-1.0.1-py3-none-any.whl -R IvelianK/PreventiveMeasure
```

## Uso

```bash
preventivemeasure serve
```

Si el comando no está en el PATH, `python -m preventivemeasure serve` hace lo mismo. Los datos se guardan en `./data` del directorio desde el que lo arrancas; cámbialo con `PM_DATA`.

Abre http://127.0.0.1:8765 con el token que imprime **solo en el primer arranque** (en la BD únicamente queda su hash). Si lo pierdes:

```bash
preventivemeasure rotate-admin-token
```

También puedes fijarlo con `PM_ADMIN_TOKEN` (mínimo 32 caracteres si el panel escucha en red). Desde el panel:

- **Activos**: añade URL, ruta de proyecto, este equipo, sube un fichero (lockfile, SBOM, APK, IPA) o copia el comando del agente.
- **Hallazgos**: filtra, abre el detalle, *Recomprobar ahora*, reconocer, ignorar, resolver, reenviar aviso, notas, exportar CSV.
- **Ajustes**: intervalo (5 a 1440 min, por defecto 30), prioridad mínima de aviso, plantilla del mensaje con variables y vista previa, canales con botón de prueba, feeds, API key de NVD.

Los campos secretos de los canales (contraseñas, tokens, URLs de webhook, topic de ntfy) admiten `env:NOMBRE_VARIABLE` para no guardarlos en la base de datos. Solo se resuelve en campos secretos y nunca para variables `PM_*`.

### Variables de entorno

| Variable | Uso |
|---|---|
| `PM_DATA` | Carpeta de datos (por defecto `./data`) |
| `PM_ADMIN_TOKEN` | Token de administración fijo en vez del generado |
| `PM_SCAN_ROOTS` | Carpetas permitidas para activos de tipo ruta, separadas por `;` (Windows) o `:` (Unix). Vacío = rutas del panel desactivadas; `check` y `agent --path` locales siguen disponibles |
| `PM_ALLOWED_HOSTS` | Nombres de host aceptados cuando el panel escucha en red (en loopback se fija solo) |
| `PM_AGENT_TOKEN` | Token del agente remoto (mejor que `--token`, que se ve en la lista de procesos) |
| `PM_ALLOW_PRIVATE_NOTIFICATIONS` | `1` permite avisos a redes privadas y HTTP solo hacia esas redes; úsalo únicamente con destinos internos de confianza |

Para vigilar una carpeta desde el panel, define `PM_SCAN_ROOTS` antes de iniciar el servidor. Ejemplo en PowerShell: `$env:PM_SCAN_ROOTS='Z:\GITHUB'`; en Linux/macOS: `export PM_SCAN_ROOTS=/srv/proyectos`. Los activos de tipo ruta ya guardados conservan su inventario, pero no vuelven a escanearse hasta configurar una raíz que los incluya. Los enlaces simbólicos dentro de un proyecto se omiten y dejan el inventario como parcial.

### Agente remoto

```bash
PM_AGENT_TOKEN=TOKEN_DE_AGENTE python3 -m preventivemeasure agent --server https://monitor.ejemplo.com --every 30 --path /srv/app
```

El token de agente solo permite enviar inventario, se rota desde Ajustes y admite un envío por host cada 60 s.

### Integración continua

```bash
preventivemeasure check . --fail-on high
```

Sale con código 1 si hay vulnerabilidades de esa severidad o superior. Solo consulta OSV, no necesita servidor.

### Docker

```bash
docker build -t preventivemeasure .
```

```bash
docker run -d -p 127.0.0.1:8765:8765 -v pm-data:/data -e PM_ALLOWED_HOSTS=127.0.0.1,localhost preventivemeasure
```

En el primer arranque el token generado aparece en los registros del contenedor. Restringe el acceso a esos registros, guárdalo en un gestor de contraseñas y rótalo si se expone. Puedes configurar `PM_ADMIN_TOKEN` mediante un fichero de entorno excluido de Git.
Para monitorizar carpetas del anfitrión desde Docker, móntalas en modo lectura y define `PM_SCAN_ROOTS` con la ruta **dentro** del contenedor, por ejemplo `-v /srv/proyectos:/projects:ro -e PM_SCAN_ROOTS=/projects`.

## Seguridad del propio monitor

- Escucha en `127.0.0.1` por defecto, con validación de cabecera `Host` contra DNS rebinding. Para recibir agentes remotos, ponlo detrás de un proxy inverso con TLS y define `PM_ALLOWED_HOSTS`.
- API con token Bearer (comparación en tiempo constante); en la BD solo el hash SHA-256 del token de administración. Token de agente separado y de alcance mínimo. Los intentos con token no válido quedan en el registro, agregados por IP y minuto.
- Cuerpos de petición limitados antes de leerse (1 MB general, 32 MB agente, 300 MB subidas).
- Avisos HTTP(S) enviados directamente a una IP validada, sin proxy ni redirecciones; por defecto, solo HTTPS hacia IPs públicas. `PM_ALLOW_PRIVATE_NOTIFICATIONS=1` habilita destinos internos de forma explícita. Los feeds y la detección web validan cada redirección, pero siguen necesitando reglas de salida de red si un proxy o un cambio de DNS puede eludir la validación.
- XML con DTD interna rechazado (billion laughs); APK/IPA leídos sin descomprimir miembros enteros (zip bombs); expresiones regulares acotadas contra ReDoS; manifiestos de más de 50 MB (100 MB SBOM) descartados.
- Un inventario parcial (fichero ilegible, recorrido truncado) nunca da por resueltas vulnerabilidades.
- `subprocess` solo con rutas absolutas fuera del directorio de trabajo, sin `.bat`/`.cmd` en Windows.
- CSP estricta (`default-src 'self'`, sin scripts ni estilos inline), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP/CORP, `Permissions-Policy`, sin documentación OpenAPI expuesta.
- La SPA inserta todo el texto externo con `textContent`; los enlaces solo admiten `http(s)`.
- Los secretos de los canales se ocultan en la API de administración (`********`). El token de agente sí se muestra al administrador para configurar los agentes. Los webhooks genéricos se firman con HMAC-SHA256 (`X-PreventiveMeasure-Signature`); Discord bloquea las menciones masivas inyectadas.
- `data/` en 0700 y la BD en 0600 en Unix. En Windows, restringe la carpeta con `icacls "data" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`.
- `data/` contiene inventarios, nombres de equipos, hallazgos y configuración de avisos. No subas esa carpeta, copias de su base de datos ni registros del servidor a un repositorio público.
- El CSV exportado neutraliza la inyección de fórmulas.

## Limitaciones conocidas

- Sin API key de NVD, el primer histórico se consulta a 25 productos por ciclo. La key aumenta el ritmo permitido por NVD.
- La detección web es pasiva: si el servidor oculta versiones, se inventaría el producto sin versión y se vigila por noticias y CVE sin analizar.
- La comparación de versiones de NVD es genérica (no semántica por ecosistema); OSV compara en su servidor con la semántica exacta.
- El nombre CPE de programas de escritorio se deduce; si no coincide con NVD, corrígelo en *Componentes > CPE* y la corrección se recuerda.
- El token de agente es compartido. Si un agente queda comprometido, podría suplantar a otro equipo y enviar un inventario falso. Limita el acceso al token, usa TLS y rota el token ante sospechas.
- Los escaneos de rutas solicitados desde el panel requieren `PM_SCAN_ROOTS`; acota su valor a los proyectos necesarios. Las subidas y el escaneo local de la CLI no requieren esa variable.

## Tests

```bash
python -m pip install -e ".[dev]"
```

```bash
python -m pytest -q tests
```

## Colaborar y comunicar vulnerabilidades

Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para proponer cambios. Si encuentras una vulnerabilidad en PreventiveMeasure, sigue [SECURITY.md](SECURITY.md) y comunícala de forma privada.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
