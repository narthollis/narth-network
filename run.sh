#!/usr/bin/env bash

sudo setcap cap_net_admin+ep target/debug/narth-net

exec target/debug/narth-net
