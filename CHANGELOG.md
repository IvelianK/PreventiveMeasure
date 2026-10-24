# Cambios

## 1.0.0

Primera versión pública.

- Inventario de webs, proyectos (más de 20 ecosistemas y SBOM CycloneDX/SPDX), APK/AAB/IPA, equipos Windows, Linux y macOS, servidores remotos con agente y componentes manuales.
- Cruce cada 30 minutos (configurable) con OSV, NVD (con datos del fabricante antes del análisis de NVD), CISA KEV, FIRST EPSS y feeds de noticias de seguridad.
- Recomendaciones por hallazgo: versión corregida, comando de actualización, acción de CISA y mitigaciones temporales por tipo de debilidad.
- Avisos por email, Telegram, WhatsApp (Twilio y CallMeBot), Discord, Slack, Teams, ntfy y webhook firmado, con plantilla editable.
- Panel web, exportación CSV y comando `check` para integración continua.
- Endurecimiento: límites de tamaño y tiempo, freno de SSRF, token de administración guardado como hash, protección frente a XML, zip y expresiones regulares hostiles, subidas con nombre fijado por el servidor e inventarios parciales que nunca dan por resuelta una vulnerabilidad.
