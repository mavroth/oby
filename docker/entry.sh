#!/bin/sh
# Home is writable by the host user. A visible session draws on :99, which
# x11vnc publishes inside the container. This shell stays so a stop signal
# can close Firefox: the recorder is often blocked inside the browser driver,
# and it only saves once that call returns.
set -eu
export HOME="${HOME:-/tmp/oby-home}"
mkdir -p "$HOME"

if [ "${OBY_HEADED:-0}" = "1" ]; then
  export DISPLAY=:99
  mkdir -p /tmp/.X11-unix
  chmod 1777 /tmp/.X11-unix 2>/dev/null || true
  setsid Xvfb :99 -screen 0 1920x1080x24 -ac -nolisten tcp >/tmp/xvfb.log 2>&1 </dev/null &
  i=0
  while [ ! -S /tmp/.X11-unix/X99 ]; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
      echo "oby: Xvfb did not start" >&2
      cat /tmp/xvfb.log >&2 || true
      exit 1
    fi
    sleep 0.1
  done
  setsid x11vnc -display :99 -nopw -forever -shared -rfbport 5900 -listen 0.0.0.0 >/tmp/x11vnc.log 2>&1 </dev/null &
  i=0
  while ! python -c "import socket; socket.create_connection(('127.0.0.1', 5900), 0.2).close()" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
      echo "oby: the screen share did not start" >&2
      cat /tmp/x11vnc.log >&2 || true
      exit 1
    fi
    sleep 0.1
  done
fi

"$@" &
child=$!

stop() {
  trap '' INT TERM
  set +e
  # A signal wedges the browser driver's cookie snapshot. The file lets
  # Python finish the save on its own stack. Signal only if that stalls.
  : > /tmp/oby-stop
  i=0
  while kill -0 "$child" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -eq 150 ]; then
      kill -TERM "$child" 2>/dev/null || true
    fi
    if [ "$i" -gt 400 ]; then
      kill -KILL "$child" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  wait "$child"
  exit $?
}

trap stop INT TERM
wait "$child"
exit $?
