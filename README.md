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

## Uso

Requiere Python 3.11+.

```bash
pip install -e .
```

```bash
preventivemeasure serve
```

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
| `PM_SCAN_ROOTS` | Carpetas permitidas para activos de tipo ruta, separadas por `;` (Windows) o `:` (Unix). Vacío = sin límite |
| `PM_ALLOWED_HOSTS` | Nombres de host aceptados cuando el panel escucha en red (en loopback se fija solo) |
| `PM_AGENT_TOKEN` | Token del agente remoto (mejor que `--token`, que se ve en la lista de procesos) |

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

## Seguridad del propio monitor

- Escucha en `127.0.0.1` por defecto, con validación de cabecera `Host` contra DNS rebinding. Para recibir agentes remotos, ponlo detrás de un proxy inverso con TLS y define `PM_ALLOWED_HOSTS`.
- API con token Bearer (comparación en tiempo constante); en la BD solo el hash SHA-256 del token de administración. Token de agente separado y de alcance mínimo. Los intentos con token no válido quedan en el registro, agregados por IP y minuto.
- Cuerpos de petición limitados antes de leerse (1 MB general, 32 MB agente, 300 MB subidas).
- Salidas HTTP con tope de tamaño y tiempo; redirecciones validadas en cada salto. Se bloquean IPs literales de metadatos cloud y, sin proxy, las direcciones detectadas por DNS. Esta validación no sustituye a las reglas de salida de red: un proxy o un cambio de DNS entre validación y conexión pueden eludirla.
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
- Un administrador puede solicitar escaneos de rutas del servidor. Define `PM_SCAN_ROOTS` si el panel se usa fuera de un equipo de confianza.

## Tests

```bash
pip install -e .[dev]
```

```bash
python -m pytest -q tests
```

## Colaborar y comunicar vulnerabilidades

Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para proponer cambios. Si encuentras una vulnerabilidad en PreventiveMeasure, sigue [SECURITY.md](SECURITY.md) y comunícala de forma privada.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
