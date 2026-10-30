"""Generate a REAL port-scan log by running nmap against a local sensor.

This is an end-to-end attack simulation, not synthetic data:

  1. Bind TCP ports on 127.0.0.1 (a tiny honeypot / sensor).
  2. Generate real traffic in three phases while the sensor logs every
     connection it accepts, in syslog format, to ``sample_data/portscan.log``:

     a. Normal traffic: a health checker polls two service ports (9100, 9101)
        throughout the run. Same two ports over and over - not a scan.
     b. Fast scan: ``nmap -sT`` across 9200-9240 in about a second.
        PORT-SCAN-0001 fires (>= 15 distinct ports in 10 s).
     c. Low-and-slow scan: ``nmap -sT --scan-delay 1s`` across 9300-9314.
        Same 15 ports, but spread over ~15 s, so no 10 s window ever holds 15
        distinct ports and the rule stays silent. This is a real evasion,
        kept on its own port range so the gap is easy to see.

Then analyse that log with the engine:

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
SERVICE_PORTS = (9100, 9101)                 # health-checked "web" and "api"
FAST_RANGE = (9200, 9240)                    # 41 ports, fast scan
SLOW_RANGE = (9300, 9314)                    # 15 ports, low-and-slow scan
PID = os.getpid()


def _ports() -> list[int]:
    return [*SERVICE_PORTS, *range(FAST_RANGE[0], FAST_RANGE[1] + 1),
            *range(SLOW_RANGE[0], SLOW_RANGE[1] + 1)]


def _open_listeners() -> list[socket.socket]:
    socks = []
    for port in _ports():
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


def _health_checker(stop: threading.Event, interval: float = 1.5) -> None:
    """Normal monitoring traffic: poll the two service ports until stopped."""
    while not stop.wait(interval):
        for port in SERVICE_PORTS:
            try:
                with socket.create_connection((HOST, port), timeout=1):
                    pass
            except OSError:
                pass


def _nmap(port_range: tuple[int, int], *extra: str) -> None:
    ports = f"{port_range[0]}-{port_range[1]}"
    cmd = ["nmap", "-sT", "-Pn", "--max-retries", "0", *extra, "-p", ports, HOST]
    print(f"running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    if shutil.which("nmap") is None:
        print("nmap not found on PATH — install it or use a connect scanner.",
              file=sys.stderr)
        return 1

    socks = _open_listeners()
    if not socks:
        print("could not bind any listener ports", file=sys.stderr)
        return 1
    print(f"sensor listening on {HOST} ({len(socks)} ports)", file=sys.stderr)

    stop = threading.Event()
    log_lines: list[str] = []
    sensor = threading.Thread(target=_sensor_loop, args=(socks, stop, log_lines))
    health_stop = threading.Event()
    health = threading.Thread(target=_health_checker, args=(health_stop,))
    sensor.start()
    health.start()

    time.sleep(5)                          # a. normal traffic only
    _nmap(FAST_RANGE)                      # b. fast scan -> detected
    time.sleep(12)                         # let the 10 s window empty out
    _nmap(SLOW_RANGE, "--scan-delay", "1s")  # c. low-and-slow -> evades
    time.sleep(4)                          # a little more normal traffic

    health_stop.set()
    health.join()
    time.sleep(1.0)                        # let the last accepts drain
    stop.set()
    sensor.join()
    for s in socks:
        s.close()

    LOG_PATH.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(f"logged {len(log_lines)} real connections -> {LOG_PATH}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
