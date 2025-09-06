# InfoSentinel Backend Dockerfile
# Multi-stage build for production-ready container

# Build stage
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    nmap \
    masscan \
    nikto \
    sqlmap \
    dirb \
    gobuster \
    wfuzz \
    hydra \
    john \
    hashcat \
    metasploit-framework \
    aircrack-ng \
    wireshark-common \
    tcpdump \
    dnsutils \
    whois \
    traceroute \
    telnet \
    openssh-client \
    rsync \
    git \
    vim \
    nano \
    htop \
    iotop \
    iftop \
    nethogs \
    ss \
    lsof \
    strace \
    ltrace \
    gdb \
    valgrind \
    binutils \
    file \
    strings \
    hexdump \
    xxd \
    objdump \
    readelf \
    nm \
    strip \
    ar \
    ranlib \
    ld \
    as \
    gcc \
    g++ \
    make \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpq5 \
    libffi8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create non-root user for security
RUN groupadd -r infosec && useradd -r -g infosec -d /app -s /bin/bash infosec

# Create application directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/uploads /app/logs /app/reports /app/temp && \
    chown -R infosec:infosec /app

# Copy application code
COPY --chown=infosec:infosec . /app/

# Install additional security tools via pip
RUN pip install --no-cache-dir \
    python-nmap \
    python-masscan \
    shodan \
    censys \
    virustotal-api \
    urlscan-py \
    dnspython \
    python-whois \
    geoip2 \
    maxminddb \
    scapy \
    impacket \
    pycryptodome \
    cryptography \
    paramiko \
    fabric \
    ansible \
    docker \
    kubernetes \
    boto3 \
    azure-identity \
    google-cloud-security-center

# Set up security tools configuration
RUN mkdir -p /app/tools && \
    # Download and setup additional tools
    curl -L https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.15_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip -d /app/tools/ && \
    rm nuclei.zip && \
    chmod +x /app/tools/nuclei && \
    # Download nuclei templates
    /app/tools/nuclei -update-templates && \
    # Download SecLists
    git clone https://github.com/danielmiessler/SecLists.git /app/tools/SecLists && \
    # Download PayloadsAllTheThings
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /app/tools/PayloadsAllTheThings && \
    # Download OWASP ZAP scripts
    mkdir -p /app/tools/zap-scripts && \
    curl -L https://github.com/zaproxy/community-scripts/archive/main.zip -o zap-scripts.zip && \
    unzip zap-scripts.zip -d /app/tools/zap-scripts/ && \
    rm zap-scripts.zip && \
    # Set permissions
    chown -R infosec:infosec /app/tools

# Install Nmap scripts
RUN mkdir -p /app/tools/nmap-scripts && \
    cp -r /usr/share/nmap/scripts/* /app/tools/nmap-scripts/ && \
    chown -R infosec:infosec /app/tools/nmap-scripts

# Create startup script
RUN cat > /app/start.sh << 'EOF'
#!/bin/bash
set -e

# Wait for database to be ready
echo "Waiting for database..."
while ! nc -z postgres 5432; do
  sleep 1
done
echo "Database is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis..."
while ! nc -z redis 6379; do
  sleep 1
done
echo "Redis is ready!"

# Run database migrations
echo "Running database migrations..."
python -c "from database_setup import db_manager; db_manager.create_tables()"

# Create default admin user if it doesn't exist
echo "Creating default admin user..."
python -c "
from database_setup import db_manager
try:
    admin_user = db_manager.create_admin_user('admin', 'admin@infosec.local', 'SecurePassword123!')
    print(f'Admin user created: {admin_user.username}')
except Exception as e:
    print(f'Admin user already exists or error: {e}')
"

# Start the application
echo "Starting InfoSentinel API server..."
exec "$@"
EOF

RUN chmod +x /app/start.sh && chown infosec:infosec /app/start.sh

# Create health check script
RUN cat > /app/healthcheck.sh << 'EOF'
#!/bin/bash
curl -f http://localhost:8000/health || exit 1
EOF

RUN chmod +x /app/healthcheck.sh && chown infosec:infosec /app/healthcheck.sh

# Switch to non-root user
USER infosec

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/healthcheck.sh

# Set entrypoint
ENTRYPOINT ["/app/start.sh"]

# Default command
CMD ["uvicorn", "main_api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# Labels for metadata
LABEL maintainer="InfoSentinel Security Team" \
      version="1.0.0" \
      description="InfoSentinel Cybersecurity Platform Backend" \
      org.opencontainers.image.title="InfoSentinel Backend" \
      org.opencontainers.image.description="Enterprise cybersecurity platform with real-time scanning and vulnerability management" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="InfoSentinel Security" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/infosec/infosec-platform" \
      org.opencontainers.image.documentation="https://docs.infosec.local" \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
      security.scan.enabled="true" \
      security.scan.tools="nmap,zap,nuclei,masscan" \
      security.compliance="owasp,nist,iso27001" \
      deployment.environment="production" \
      deployment.tier="backend" \
      monitoring.metrics="prometheus" \
      monitoring.logs="elasticsearch" \
      monitoring.tracing="jaeger"