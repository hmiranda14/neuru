#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — HTTPS enablement (recreate-safe, entrypoint-driven).
#
# WHY: the AI Commander voice add-on (VAPI/WebRTC) needs microphone access, and
# browsers only grant getUserMedia in a SECURE CONTEXT (HTTPS or localhost). NEURU
# ships on http:// by default → no mic → no voice. This script gives Apache a
# self-signed TLS vhost on :443 so https://SERVER:8453 works (accept-the-warning
# once, standard appliance pattern). Everything else keeps working on :80.
#
# RECREATE-SAFE: /etc/apache2 is NOT a bind-mount (lost on container recreate), so
# the vhost is (re)written here on every boot. The CERT lives in the bind-mounted
# app dir ($APP/.nm_tls) so the browser exception the operator accepted STAYS valid
# across recreates (a fresh cert each boot would force re-accepting every time).
# A customer can drop their OWN cert/key at $APP/.nm_tls/neuru.{crt,key} and we
# reuse it untouched.
#
# Idempotent; must run as root (the entrypoint already does). Called from
# netmon-entrypoint.sh before apache starts.
# ─────────────────────────────────────────────────────────────────────────────
set +e
APP=/var/www/html/netmon
TLS="$APP/.nm_tls"
CRT="$TLS/neuru.crt"
KEY="$TLS/neuru.key"

command -v openssl >/dev/null 2>&1 || { echo "[https] openssl missing — cannot enable TLS"; exit 0; }

mkdir -p "$TLS" 2>/dev/null

# 1) self-signed cert (generate once; never clobber an operator-supplied cert)
if [ ! -s "$CRT" ] || [ ! -s "$KEY" ]; then
    # SAN: cover the loopback + this container's own addresses. The operator reaches
    # NEURU by the HOST ip:port, which the container can't know — a self-signed cert
    # warns on any host anyway, so SAN correctness is cosmetic (accepted once).
    SAN="DNS:neuru,DNS:neuru-web,DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null); do SAN="$SAN,IP:$ip"; done
    [ -n "$NEURU_TLS_SAN" ] && SAN="$SAN,$NEURU_TLS_SAN"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$KEY" -out "$CRT" \
        -subj "/O=NEURU/CN=neuru" \
        -addext "subjectAltName=$SAN" >/dev/null 2>&1 \
        && echo "[https] generated self-signed cert ($SAN)" \
        || echo "[https] WARNING: cert generation failed"
fi
# www-data must READ the cert; the KEY stays root-only readable
chown www-data:www-data "$CRT" 2>/dev/null; chmod 644 "$CRT" 2>/dev/null
chmod 600 "$KEY" 2>/dev/null

# 2) modules (idempotent; already baked in the Dockerfile, re-asserted for old images)
a2enmod ssl headers >/dev/null 2>&1

# 3) SSL vhost → same docroot as :80. Written every boot (config isn't persisted).
cat > /etc/apache2/sites-available/neuru-ssl.conf <<EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
    DocumentRoot /var/www/html/netmon
    SSLEngine on
    SSLCertificateFile    $CRT
    SSLCertificateKeyFile $KEY
    <Directory /var/www/html/netmon>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
</IfModule>
EOF
a2ensite neuru-ssl >/dev/null 2>&1 && echo "[https] SSL vhost enabled (:443 → $APP)"
