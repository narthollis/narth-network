#!/usr/bin/env bash

sudo setcap cap_net_admin+ep target/debug/narth-net

RUST_BACKTRACE=1 exec target/debug/narth-net "$@"
