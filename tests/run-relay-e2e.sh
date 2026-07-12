#!/bin/bash
# Boot a loopback relay (nak serve) and run relay-e2e.tcl against it.
#
#   NAK=/path/to/nak TCLSH=/path/to/tclsh9.0 tests/run-relay-e2e.sh
#
# Requires: a `nak` with the `serve` subcommand, a tclsh that can load
# the built libnostr and reach the tcllib modules (set TCLLIB_MODULES
# to a colon-separated list of module dirs, or rely on the defaults
# below).  Everything runs in one process group so the relay dies with
# the script.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NAK="${NAK:-nak}"
TCLSH="${TCLSH:-tclsh9.0}"
PORT="${PORT:-10547}"
LIBNOSTR="${LIBNOSTR:-$ROOT/libnostr[info sharedlibextension]}"
# resolve the actual shared lib if the caller did not pin one
if [ ! -f "$LIBNOSTR" ]; then
    LIBNOSTR="$(ls "$ROOT"/libnostr.so "$ROOT"/libnostr.dylib 2>/dev/null | head -1)"
fi

export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$(mktemp -d)}"
LOG="$(mktemp)"

AUTHPORT="${AUTHPORT:-$((PORT + 1))}"
LOG2="$(mktemp)"

"$NAK" serve --port "$PORT" >"$LOG" 2>&1 &
p1=$(jobs -p | tail -1)
"$NAK" serve --port "$AUTHPORT" --auth --eager-auth >"$LOG2" 2>&1 &
p2=$(jobs -p | tail -1)
trap 'kill $p1 $p2 2>/dev/null' EXIT

up() {
    for i in $(seq 1 30); do
        if grep -qi 'relay running' "$1"; then return 0; fi
        sleep 0.2
    done
    echo "nak serve did not come up:" >&2; cat "$1" >&2; return 1
}
up "$LOG" || exit 1
up "$LOG2" || exit 1

RELAY_URL="ws://localhost:$PORT" \
AUTH_URL="ws://localhost:$AUTHPORT" \
LIBNOSTR="$LIBNOSTR" \
TCLLIB_MODULES="${TCLLIB_MODULES:-}" \
    "$TCLSH" "$HERE/relay-e2e.tcl"
rc=$?
exit $rc
