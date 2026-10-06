#!/bin/bash
# Netns test stand for the tunnel under load. Do not run directly — use `run.sh`
# (this script must run inside `unshare -Urnm`). args: <client binary> <label>
#
# env: RATE (downlink, tc rate), UPRATE, DELAY (one-way), NETEM_LIMIT (packets),
#      LOADN, LOADSEC, MODE (down|up), BIGBYTES, LOGLEVEL, SERVER (server binary),
#      ONLY (command to run in the client netns instead of the standard scenario),
#      THREADS=1 (per-thread CPU breakdown).
CLIENT=$1; LABEL=$2
HERE=$(cd "$(dirname "$0")" && pwd)
D=${OUT:-$PWD/stand-out}; mkdir -p "$D"
SERVER=${SERVER:-$HERE/../../target/release/netrunner-server}
RATE=${RATE:-100mbit}; UPRATE=${UPRATE:-50mbit}; DELAY=${DELAY:-25ms}
LOADN=${LOADN:-8}; LOADSEC=${LOADSEC:-20}; MODE=${MODE:-down}
W=$(mktemp -d /tmp/nr-stand.XXXXXX)
cleanup() { kill $CPID $SPID $HPID $EPID $UPID 2>/dev/null; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

mount -t tmpfs tmpfs /run; mkdir -p /run/netns
ip link set lo up
ip netns add cl
ip link add vs type veth peer name vc
ip link set vc netns cl
ip addr add 198.18.0.1/24 dev vs; ip link set vs up
ip addr add 203.0.113.80/32 dev lo
ip netns exec cl sh -c "ip link set lo up; ip addr add 198.18.0.2/24 dev vc; ip link set vc up; ip route add default via 198.18.0.1"
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
# shape the physical link: server->client (downlink) on vs, client->server (uplink) on vc
tc qdisc add dev vs root netem delay $DELAY rate $RATE limit ${NETEM_LIMIT:-400}
ip netns exec cl tc qdisc add dev vc root netem delay $DELAY rate $UPRATE limit ${NETEM_LIMIT:-400}

mkdir -p $W/www $W/nrcache
head -c ${BIGBYTES:-400000000} /dev/zero > $W/www/big; echo ok > $W/www/small
cat > $W/www/srv.py <<'PY'
import http.server, socketserver
class H(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        while n > 0:
            c = self.rfile.read(min(n, 1 << 20)); n -= len(c)
            if not c: break
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True; request_queue_size = 128
S(("203.0.113.80", 8080), H).serve_forever()
PY
( cd $W/www && exec python3 srv.py >/dev/null 2>&1 ) & HPID=$!
python3 $HERE/udp_echo.py 203.0.113.80 9999 & EPID=$!
$SERVER --host 198.18.0.1 --port 18443 --decoy-host www.debian.org >$D/server_$LABEL.log 2>&1 & SPID=$!
cat > $W/c.toml <<CFG
remote_address = "198.18.0.1:18443"
sni = "www.debian.org"
auth_token = ""
node_secret = ""
node_public_key = ""
cache_dir = "$W/nrcache"
mtu = 1450
killswitch_enabled = false
log_level = "${LOGLEVEL:-error}"
tunnel_mode = "all"
router_mode = false
CFG
sleep 1.5
ip netns exec cl $CLIENT --config $W/c.toml >$D/client_$LABEL.log 2>&1 & CPID=$!
ok=0; for i in $(seq 1 40); do
  if ip netns exec cl curl -s -m 3 -o /dev/null http://203.0.113.80:8080/small; then ok=1; break; fi; sleep 0.5; done
[ $ok = 1 ] || { echo "$LABEL: tunnel did not come up"; tail -5 $D/client_$LABEL.log; exit 1; }
sleep 3
if [ -n "$ONLY" ]; then ip netns exec cl $ONLY; exit 0; fi
echo "=== $LABEL  down=$RATE up=$UPRATE one-way-delay=$DELAY load=$LOADN x $MODE for ${LOADSEC}s"
ip netns exec cl python3 $HERE/probe.py "idle" 8 203.0.113.80 8080 9999

# load: LOADN parallel transfers (speedtest-like)
TCK=$(getconf CLK_TCK); cpu_ticks() { awk '{print $14+$15}' /proc/$CPID/stat 2>/dev/null; }
CPU0=$(cpu_ticks); T0=$(date +%s.%N)
LP=()
for i in $(seq 1 $LOADN); do
  case $MODE in
    down) ip netns exec cl curl -s -m $LOADSEC -o /dev/null -w "dl$i %{size_download}B %{speed_download}B/s exit=%{exitcode}\n" http://203.0.113.80:8080/big >> $D/load_$LABEL.out 2>&1 & LP+=($!);;
    up)   ip netns exec cl curl -s -m $LOADSEC -o /dev/null -X POST -T $W/www/big -H 'Expect:' -w "ul$i %{size_upload}B %{speed_upload}B/s exit=%{exitcode}\n" http://203.0.113.80:8080/up >> $D/load_$LABEL.out 2>&1 & LP+=($!);;
  esac
done
sleep 4
ip netns exec cl python3 $HERE/probe.py "under-load" $((LOADSEC-6)) 203.0.113.80 8080 9999
for p in "${LP[@]}"; do wait $p 2>/dev/null; done
cat $D/load_$LABEL.out | sort | tr '\n' ' '; echo
CPU1=$(cpu_ticks); T1=$(date +%s.%N)
BYTES=$(awk '{gsub("B","",$2); s+=$2} END{print s+0}' $D/load_$LABEL.out)
[ -n "$THREADS" ] && { echo "-- client threads (user sys):"; bash $HERE/threads.sh $CPID; echo "-- server threads:"; bash $HERE/threads.sh $SPID; }
echo "client CPU during load: $(awk -v a=$CPU0 -v b=$CPU1 -v t=$TCK 'BEGIN{printf "%.2f", (b-a)/t}') cpu-s for $((BYTES/1048576)) MB => $(awk -v a=$CPU0 -v b=$CPU1 -v t=$TCK -v by=$BYTES 'BEGIN{ if (by>0) printf "%.2f", ((b-a)/t)/(by/1073741824); else print "n/a"}') cpu-s/GB"

sleep 3
ip netns exec cl python3 $HERE/probe.py "after" 6 203.0.113.80 8080 9999
