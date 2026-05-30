#!/usr/bin/env bash

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

RUST_BACKTRACE="${RUST_BACKTRACE:-1}" exec target/debug/narth-net "$@" &
  # | grep -vE '^>|^<'
  #  2> >(sed -u $'s/.*/\e[31m&\e[0m/' >&2) \
PID=$!

sudo sysctl -w net.ipv4.conf.narth0.forwarding=1
sudo sysctl -w net.ipv4.conf.narth0.route_localnet=1

wait "$PID"

trap - SIGINT SIGTERM
