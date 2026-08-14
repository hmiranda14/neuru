# NEURU-in-a-Box — the WHOLE platform in ONE container (Apache + PHP 8.3 + embedded
# MariaDB + Python daemons + cron). Self-initializes the DB + schema on first boot.
# Deploy on Ubuntu/Docker, a Raspberry Pi (arm64), or a MikroTik x86 CHR. Multi-arch.
# Build context = the repo root (the app tree is baked in). n8n stays external/hosted.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=America/Puerto_Rico

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tzdata \
        apache2 php libapache2-mod-php php-cli php-common php-mysql \
        php-mbstring php-xml php-zip php-gd php-bcmath php-intl php-curl \
        mariadb-server mariadb-client \
        curl nano less rsync openssl cron \
        python3 python3-venv python3-pip python3-paramiko python3-cryptography \
        snmp iputils-ping \
    && a2enmod rewrite ssl headers \
    && sed -i 's#DocumentRoot /var/www/html#DocumentRoot /var/www/html/netmon#g' /etc/apache2/sites-available/000-default.conf \
    && printf '<Directory /var/www/html/netmon>\n    Options Indexes FollowSymLinks\n    AllowOverride All\n    Require all granted\n</Directory>\n' > /etc/apache2/conf-available/netmon.conf \
    && a2enconf netmon \
    && useradd -m -s /bin/bash neuru && echo 'neuru:admin@1.one' | chpasswd && usermod -aG sudo neuru \
    && python3 -m venv --system-site-packages /opt/netmon-venv \
    && /opt/netmon-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/netmon-venv/bin/pip install --no-cache-dir mysql-connector-python \
    && /opt/netmon-venv/bin/python3 -c "import paramiko, mysql.connector; print('[build] python deps OK')" \
    && rm -rf /var/lib/apt/lists/*

# Bake the app tree (context = repo root) + the box crontab for the neuru user.
COPY . /var/www/html/netmon
COPY scripts/neuru-box/netmon.cron /home/neuru/netmon.cron
RUN rm -f /var/www/html/netmon/connection.php /var/www/html/netmon/connection-users.php \
    && chmod +x /var/www/html/netmon/scripts/*.sh /var/www/html/netmon/scripts/neuru-box/*.sh 2>/dev/null || true \
    && chown -R neuru:neuru /home/neuru \
    && mkdir -p /home/neuru/netmon-logs

VOLUME ["/var/lib/mysql"]
EXPOSE 80 443 2055/udp 514/udp 514/tcp
CMD ["/bin/bash", "/var/www/html/netmon/scripts/neuru-box/entrypoint.sh"]
