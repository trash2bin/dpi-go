#!/usr/bin/env bash
set -euo pipefail

# IP forwarding
echo "[entrypoint] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

# NAT — код этого не делает, поэтому делаем здесь
# Определяем внешний интерфейс динамически (не хардкодим eth0/eth1)
EXTERNAL_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)

if [ -z "$EXTERNAL_IFACE" ]; then
  echo "[entrypoint] WARNING: cannot detect external interface, skipping NAT"
else
  echo "[entrypoint] External interface: $EXTERNAL_IFACE, setting up NAT..."
  nft add table ip nat 2>/dev/null || true
  nft add chain ip nat postrouting "{ type nat hook postrouting priority 100; policy accept; }" 2>/dev/null || true
  nft add rule ip nat postrouting oifname "$EXTERNAL_IFACE" masquerade 2>/dev/null || true
  echo "[entrypoint] NAT configured"
fi

# dnsmasq
echo "[entrypoint] Starting dnsmasq..."
mkdir -p /run/dnsmasq /etc/dnsmasq.d
if ! pgrep -x dnsmasq >/dev/null 2>&1; then
  dnsmasq --conf-file=/etc/dnsmasq.conf --keep-in-foreground >/tmp/dnsmasq.log 2>&1 &
fi

# Запуск программы
echo "[entrypoint] Starting: $*"
exec "$@"
