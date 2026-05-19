#!/bin/sh
set -e

# Docker bridge network has no IPv6 routing. Prefer IPv4 via gai.conf so Squid
# doesn't try unreachable IPv6 addresses before falling back to IPv4.
# This prevents CONNECT 500 errors on splice-mode connections to IPv6-only DNS results.
cat > /etc/gai.conf << 'EOF'
label  ::1/128       0
label  ::/0          1
label  2002::/16     2
label ::/96          3
label ::ffff:0:0/96  4
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence ::/96          20
# Prefer IPv4 (::ffff:0:0/96 covers all IPv4-mapped addresses)
precedence ::ffff:0:0/96  100
EOF

SSL_DB=/var/lib/squid/ssl_db

# Initialize SSL cert database on first run
if [ ! -d "$SSL_DB" ]; then
    echo "[entrypoint] Initializing SSL cert database..."
    mkdir -p "$(dirname $SSL_DB)"
    /usr/lib/squid/security_file_certgen -c -s "$SSL_DB" -M 4MB
    chown -R proxy:proxy "$SSL_DB"
    echo "[entrypoint] SSL DB initialized at $SSL_DB"
fi

# Initialize cache directories if needed
if [ ! -d /var/cache/squid/00 ]; then
    echo "[entrypoint] Initializing cache..."
    squid -N -f /etc/squid/squid.conf -z 2>&1 || true
fi

echo "[entrypoint] Starting Squid..."
exec /usr/sbin/squid -N -f /etc/squid/squid.conf
