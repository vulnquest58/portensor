#!/usr/bin/env bash
# SYN loss-resilience lab: measures how many open ports rayscan recovers when
# the network drops SYN and SYN-ACK packets.
#
# Topology:
#
#   host netns                     peer netns
#   10.200.0.1/30  <--- veth --->  10.200.0.2/30
#        rsyn-h                        rsyn-n
#   (tc netem loss)               Python listeners + (tc netem loss)
#
# The scan runs from the host namespace against 10.200.0.2. Loopback cannot be
# used for this test: the kernel answers raw SYNs locally, so the scanner's
# AF_PACKET reader never sees the SYN-ACKs.
#
# Requires Linux, root (network namespaces + netem), iproute2, and python3.
#
# Usage:
#   sudo bash scripts/syn-loss-lab.sh                       # 20% loss, --retries 2
#   sudo bash scripts/syn-loss-lab.sh --loss 5 --retries 0
#   sudo bash scripts/syn-loss-lab.sh --matrix              # report table for the gate
#
# Options:
#   --loss PCT        packet loss per direction, 0-100 (default 20)
#   --retries N       scan retransmission passes (default 2)
#   --ports RANGE     contiguous open-port range (default 9000-9019)
#   --timeout-ms MS   per-connect timeout ceiling (default 500)
#   --binary PATH     rayscan binary (default: newest of target/release, target/debug)
#   --matrix          losses 0/5/20 x retries 0/2, one line per run
#   -h, --help        show this help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="${RAYSCAN_BIN:-}"
LOSS=20
RETRIES=2
PORTS="9000-9019"
TIMEOUT_MS=500
MATRIX=0

NETNS="rayscan-loss"
HOST_IF="rsyn-h"
PEER_IF="rsyn-n"
HOST_IP="10.200.0.1"
PEER_IP="10.200.0.2"
WORKDIR=""
SERVER_PID=""

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

die() {
    echo "syn-loss-lab: $*" >&2
    exit 1
}

teardown_lab() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    ip netns del "$NETNS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
}

cleanup() {
    teardown_lab
    if [ -n "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
        WORKDIR=""
    fi
}

trap cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
        --loss) LOSS="$2"; shift 2 ;;
        --retries) RETRIES="$2"; shift 2 ;;
        --ports) PORTS="$2"; shift 2 ;;
        --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --matrix) MATRIX=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (network namespaces and netem)"
command -v ip >/dev/null || die "iproute2 (ip) is required"
command -v tc >/dev/null || die "iproute2 (tc) is required"
command -v python3 >/dev/null || die "python3 is required"

if [ -z "$BINARY" ]; then
    # Benchmarks must measure the source tree as checked out, so pick whichever
    # profile most recently finished linking instead of always preferring
    # release (a stale release binary silently hides new fixes).
    newest=0
    for candidate in "$REPO_DIR/target/release/rayscan" "$REPO_DIR/target/debug/rayscan"; do
        if [ -x "$candidate" ]; then
            modified=$(stat -c %Y "$candidate")
            if [ "$modified" -gt "$newest" ]; then
                newest="$modified"
                BINARY="$candidate"
            fi
        fi
    done
fi
[ -x "$BINARY" ] || die "rayscan binary not found; build it or pass --binary PATH"

case "$PORTS" in
    *-*) ;;
    *) die "--ports must be a contiguous range like 9000-9019" ;;
esac
START="${PORTS%-*}"
END="${PORTS#*-}"
[ "$START" -le "$END" ] || die "--ports range is backwards"

if [ "$MATRIX" -eq 1 ]; then
    LOSSES=(0 5 20)
    RETRY_SET=(0 2)
else
    LOSSES=("$LOSS")
    RETRY_SET=("$RETRIES")
fi

WORKDIR="$(mktemp -d)"

cat > "$WORKDIR/servers.py" <<'PY'
import socket
import sys
import threading
import time

start, end = int(sys.argv[1]), int(sys.argv[2])
sockets = []
for port in range(start, end + 1):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    sockets.append(sock)

def accept_loop(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        conn.close()

for sock in sockets:
    threading.Thread(target=accept_loop, args=(sock,), daemon=True).start()

print("ready", flush=True)
time.sleep(3600)
PY

cat > "$WORKDIR/report.py" <<'PY'
import json
import sys

start, end = int(sys.argv[1]), int(sys.argv[2])
report = json.load(sys.stdin)
opened = sorted(result["port"] for result in report.get("open", []))
expected = list(range(start, end + 1))
missed = [port for port in expected if port not in opened]
line = "open=%d/%d elapsed=%sms" % (len(opened), len(expected), report["elapsed_ms"])
if missed:
    line += " missed=" + ",".join(str(port) for port in missed)
print(line)
PY

setup_lab() {
    ip netns add "$NETNS"
    ip link add "$HOST_IF" type veth peer name "$PEER_IF"
    ip link set "$PEER_IF" netns "$NETNS"
    ip addr add "$HOST_IP/30" dev "$HOST_IF"
    ip link set "$HOST_IF" up
    ip netns exec "$NETNS" ip addr add "$PEER_IP/30" dev "$PEER_IF"
    ip netns exec "$NETNS" ip link set "$PEER_IF" up
    ip netns exec "$NETNS" ip link set lo up
    ip netns exec "$NETNS" python3 "$WORKDIR/servers.py" "$START" "$END" >/dev/null 2>&1 &
    SERVER_PID=$!
    sleep 1
    # Learn the neighbor entry before loss is applied; otherwise an unlucky
    # dropped ARP request aborts the whole scan.
    ping -c 2 -W 1 -q "$PEER_IP" >/dev/null
}

run_case() {
    local loss="$1"
    local retries="$2"
    local output

    setup_lab
    if [ "$loss" -gt 0 ]; then
        tc qdisc add dev "$HOST_IF" root netem loss "${loss}%"
        ip netns exec "$NETNS" tc qdisc add dev "$PEER_IF" root netem loss "${loss}%"
    fi

    if ! output=$("$BINARY" scan --syn --target "$PEER_IP" --ports "$PORTS" \
        --retries "$retries" --connect-timeout-ms "$TIMEOUT_MS" --json --quiet 2>&1); then
        echo "loss=${loss}% retries=${retries} scan failed:" >&2
        echo "$output" >&2
        teardown_lab
        return 1
    fi

    printf 'loss=%s%% retries=%s ' "$loss" "$retries"
    printf '%s' "$output" | python3 "$WORKDIR/report.py" "$START" "$END"
    teardown_lab
}

for loss in "${LOSSES[@]}"; do
    for retries in "${RETRY_SET[@]}"; do
        run_case "$loss" "$retries"
    done
done
