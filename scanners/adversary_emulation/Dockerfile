# Adversary Emulation Container
FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m adversary
USER adversary

COPY . .

ENTRYPOINT ["python", "core_engine.py"]