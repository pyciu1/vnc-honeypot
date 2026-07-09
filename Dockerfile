FROM python:3.11-slim

LABEL description="VNC Honeypot — Dual Capture + Intelligence"

# Dependente sistem
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmaxminddb0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependente Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Codul
COPY vnc_*.py ./

# Date persistente
VOLUME ["/data"]

# Porturi
EXPOSE 5800 5900 5901 5902 5903 5904 5905 5906 5907 5908 5909 5910

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 vnc_honeypot.py --self-test || exit 1

ENTRYPOINT ["python3", "vnc_honeypot.py"]
CMD [
    "--db", "/data/vnc_honeypot.db",
    "--ports", "5900-5910",
    "--http-port", "5800"
]
