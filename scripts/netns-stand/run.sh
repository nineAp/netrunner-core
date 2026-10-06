#!/bin/bash
# Runs the load scenario in a throw-away user+network namespace (no root needed):
#   scripts/netns-stand/run.sh <netrunner-client> <label> [env VAR=value ...]
#
# A veth link between the "internet" side (server + a python HTTP/UDP-echo target on
# 203.0.113.80) and a client namespace is shaped with netem. The client runs with
# `tunnel_mode = all`, so everything the scenario does goes through the tunnel. The
# standard scenario starts LOADN parallel transfers (speedtest-like) and, while they
# run, measures the latency of small TCP requests and UDP echoes — idle / under load /
# after — plus the client's CPU per GB.
#
# Examples (client and server are the release binaries):
#   # 100 Mbit / 50 ms RTT, 8 parallel downloads
#   RATE=100mbit UPRATE=50mbit DELAY=25ms scripts/netns-stand/run.sh target/release/netrunner-client dl
#   # 2 Gbit: finds where the client engine becomes the bottleneck
#   RATE=2000mbit UPRATE=1000mbit DELAY=5ms NETEM_LIMIT=2000 scripts/netns-stand/run.sh ... fast
#   # uploads
#   MODE=up RATE=1000mbit UPRATE=500mbit DELAY=5ms scripts/netns-stand/run.sh ... up
#   # slow readers (4 x 3 MB/s) next to a fast one: nobody may be killed
#   ONLY="bash scripts/netns-stand/slow_readers.sh" scripts/netns-stand/run.sh ... slow
#
# Needs: unshare, ip, tc (netem), curl, python3. Results go to ./stand-out (or $OUT).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
[ $# -ge 2 ] || { sed -n '2,22p' "$0"; exit 2; }
CLIENT=$(readlink -f "$1"); LABEL=$2
export ONLY
exec unshare -Urnm bash "$HERE/stand.sh" "$CLIENT" "$LABEL"
