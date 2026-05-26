#!/bin/sh
set -eu

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

busybox ip addr add 127.0.0.1/32 dev lo 2>/dev/null || true
busybox ip link set dev lo up
echo "127.0.0.1 localhost" > /etc/hosts

socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:127.0.0.1:3000 &

exec /nautilus-app
