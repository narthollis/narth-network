#!/usr/bin/env bash

# CONFIG

BRIDGE="narth-br0"
PHYS_INTERFACE="enp8s0f1u2u1u2"
TAP_INTERFACE="narth0"

# DO things

sudo setcap cap_net_admin+ep target/debug/narth-net

cleanup() {
    echo "$PID"
    if [ -n "$PID" ]; then
        kill "$PID"
        wait "$PID"
    fi

    exit 130
}
trap cleanup SIGINT SIGTERM

if ! ip link show "$BRIDGE"; then
  sudo ip link add name "$BRIDGE" type bridge
  sudo ip link set dev "$BRIDGE" up
fi
if ! ip link show "$PHYS_INTERFACE" | grep -q master; then
  sudo ip link set dev "$PHYS_INTERFACE" master "$BRIDGE"
  sudo ip link set dev "$PHYS_INTERFACE" up
fi

RUST_BACKTRACE="${RUST_BACKTRACE:-1}" exec target/debug/narth-net "$@" &
  # | grep -vE '^>|^<'
  #  2> >(sed -u $'s/.*/\e[31m&\e[0m/' >&2) \
PID=$!

echo "Waiting for $TAP_INTERFACE"
for i in {1..50}; do
    if ip link show "$TAP_INTERFACE" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

sudo ip link set dev "$TAP_INTERFACE" master "$BRIDGE"
#sudo ip link set dev "$TAP_INTERFACE" ip

#sudo sysctl -w net.ipv4.conf.narth0.forwarding=1
#sudo sysctl -w net.ipv4.conf.narth0.route_localnet=1

wait "$PID"

trap - SIGINT SIGTERM
