FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    dnsutils bsdmainutils curl git openssl procps \
    && rm -rf /var/lib/apt/lists/*

# Clone testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# Set up app
WORKDIR /app
COPY backend/requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt gunicorn

COPY backend/ .

ENV TESTSSL_PATH=/opt/testssl.sh/testssl.sh
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "300", "--workers", "2", "app:app"]
