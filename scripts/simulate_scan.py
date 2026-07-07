"""Generate a REAL port-scan log by running nmap against a local sensor.

This is an end-to-end attack simulation, not synthetic data:

  1. Bind a range of TCP ports on 127.0.0.1 (a tiny honeypot / sensor).
  2. Run an actual ``nmap`` connect-scan against that range.
  3. The sensor logs every real connection nmap makes, in syslog format, to
     ``sample_data/portscan.log``.

Then analyse that log with the engine to see the PORT-SCAN-0001 rule fire:

    python scripts/simulate_scan.py
    python -m siem_hunter.cli --log sample_data/portscan.log --rules rules

Only localhost is scanned, so this is self-contained and safe to run.
"""

from __future__ import annotations

import os
import selectors
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "sample_data" / "portscan.log"
HOST = "127.0.0.1"
PORT_START, PORT_END = 9200, 9240          # 41 ports
PID = os.getpid()


def _open_listeners() -> list[socket.socket]:
    socks = []
    for port in range(PORT_START, PORT_END + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, port))
            s.listen(16)
            s.setblocking(False)
            socks.append(s)
        except OSError:
            s.close()  # port busy — skip it
    return socks


def _sensor_loop(socks: list[socket.socket], stop: threading.Event,
                 log_lines: list[str]) -> None:
    """Accept connections and record one syslog line per connection."""
    sel = selectors.DefaultSelector()
    for s in socks:
        sel.register(s, selectors.EVENT_READ)
    while not stop.is_set():
        for key, _ in sel.select(timeout=0.2):
            listener = key.fileobj
            try:
                conn, addr = listener.accept()
            except OSError:
                continue
            local_port = listener.getsockname()[1]
            src_ip = addr[0]
            ts = datetime.now().strftime("%b %d %H:%M:%S")
            log_lines.append(
                f"{ts} sensor honeypot[{PID}]: TCP connection from "
                f"{src_ip} to port {local_port}"
            )
            conn.close()
    sel.close()


def main() -> int:
    if shutil.which("nmap") is None:
        print("nmap not found on PATH — install it or use a connect scanner.",
              file=sys.stderr)
        return 1

    socks = _open_listeners()
    if not socks:
        print("could not bind any listener ports", file=sys.stderr)
        return 1
    print(f"sensor listening on {HOST}:{PORT_START}-{PORT_END} "
          f"({len(socks)} ports)", file=sys.stderr)

    stop = threading.Event()
    log_lines: list[str] = []
    t = threading.Thread(target=_sensor_loop, args=(socks, stop, log_lines))
    t.start()

    ports = f"{PORT_START}-{PORT_END}"
    print(f"running: nmap -sT -Pn -p{ports} {HOST}", file=sys.stderr)
    subprocess.run(
        ["nmap", "-sT", "-Pn", "-p", ports, HOST],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    time.sleep(1.0)          # let the last accepts drain
    stop.set()
    t.join()
    for s in socks:
        s.close()

    LOG_PATH.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(f"logged {len(log_lines)} real connections -> {LOG_PATH}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
