#!/usr/bin/env bash

sudo setcap cap_net_admin+ep target/debug/narth-net

RUST_BACKTRACE="${RUST_BACKTRACE:-1}" exec target/debug/narth-net "$@" \
 | grep -vE '^>|^<'
#  2> >(sed -u $'s/.*/\e[31m&\e[0m/' >&2) \
