#!/bin/sh
set -eu

export PATH=/bin:/sbin:/usr/bin:/usr/sbin

busybox ip addr add 127.0.0.1/32 dev lo 2>/dev/null || true
busybox ip link set dev lo up
echo "127.0.0.1 localhost" > /etc/hosts

exec /nautilus-app
