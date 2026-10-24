# Colaborar

Abre una incidencia para comentar cambios grandes antes de implementarlos.
Envía cambios pequeños mediante una solicitud de incorporación contra `main`.

Instala las dependencias de desarrollo y ejecuta las pruebas antes de enviarla:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q tests
```

Usa datos sintéticos en pruebas y ejemplos. No adjuntes inventarios, registros,
capturas de paneles reales, tokens ni informes de clientes.

Para comunicar vulnerabilidades, sigue [SECURITY.md](SECURITY.md).
