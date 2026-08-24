#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for command in cc python3 strace timeout; do
  command -v "$command" >/dev/null 2>&1 || { echo "error: $command is required" >&2; exit 2; }
done

work=$(mktemp -d)
server_pid=''
cleanup() {
  [[ -z "$server_pid" ]] || kill "$server_pid" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

probe="$work/rift-loopback-probe"
cc -std=c11 -O2 -Wall -Wextra -Werror "$root/tools/sandbox-probes/rift-loopback-probe.c" -o "$probe"

cat > "$work/server.py" <<'PY'
import pathlib
import socket
import sys

ready = pathlib.Path(sys.argv[1])
received = pathlib.Path(sys.argv[2])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 0))
server.listen(1)
server.settimeout(4)
ready.write_text(str(server.getsockname()[1]), encoding="utf-8")
connection, _ = server.accept()
connection.settimeout(1)
try:
    received.write_text(str(len(connection.recv(1))), encoding="utf-8")
except TimeoutError:
    received.write_text("timeout", encoding="utf-8")
finally:
    connection.close()
    server.close()
PY

python3 "$work/server.py" "$work/port" "$work/received" &
server_pid=$!
for _ in $(seq 1 40); do
  [[ -s "$work/port" ]] && break
  sleep 0.05
done
[[ -s "$work/port" ]] || { echo "error: loopback test server did not start" >&2; exit 1; }

port=$(cat "$work/port")
strace -ff -qq -s 256 -o "$work/trace" -e trace=network \
  "$probe" --duration-ms 1000 --interval-ms 25 --connect-timeout-ms 100 -- /bin/sleep 1
wait "$server_pid"
server_pid=''

[[ $(cat "$work/received") == "0" ]] || { echo "error: loopback probe transmitted application data" >&2; exit 1; }
grep -R --quiet "htons($port).*127.0.0.1" "$work"/trace.* || {
  echo "error: loopback probe did not connect to the dynamically discovered listener" >&2
  exit 1
}
echo "Rift dynamic loopback probe self-test: PASS"
