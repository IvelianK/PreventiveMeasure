FROM python:3.12-slim
RUN useradd --create-home --uid 10001 pm
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY preventivemeasure ./preventivemeasure
RUN python -m venv /opt/pm-venv \
    && /opt/pm-venv/bin/python -m pip install --disable-pip-version-check --no-cache-dir . \
    && mkdir /data && chown pm /data
ENV PATH="/opt/pm-venv/bin:$PATH"
USER pm
ENV PM_DATA=/data
VOLUME /data
EXPOSE 8765
# 0.0.0.0 solo dentro del contenedor; publica el puerto detrás de un proxy con TLS
CMD ["preventivemeasure", "serve", "--host", "0.0.0.0", "--port", "8765"]
