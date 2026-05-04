#!/bin/sh
set -e

DPI_IP="172.28.1.2"
TARGET_NET="172.28.2.0/24"

echo "[client] Routing target subnet through DPI ($DPI_IP)..."
ip route add $TARGET_NET via $DPI_IP 2>/dev/null || true

ip route del default 2>/dev/null || true
ip route add default via $DPI_IP

echo "[client] Current routes:"
ip route

exec "$@"
