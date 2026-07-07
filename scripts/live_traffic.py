"""Continuously write realistic activity into a live log the monitor tails.

Emits mostly-benign syslog with periodic attack bursts (brute force, password
spray, port scan, root-account creation), all timestamped 'now', so the live
monitor detects them in real time. Clearly synthetic — for demos / the report.

    python scripts/live_traffic.py --out logs/live.log
"""

from __future__ import annotations

import argparse
import itertools
import random
import time
from datetime import datetime
from pathlib import Path

BENIGN_USERS = ["alice", "bob", "carol", "deploy", "svc-web"]
BENIGN_IPS = ["10.0.5.11", "10.0.5.12", "10.0.5.20", "10.0.7.31"]
ATTACKER_IPS = ["45.83.19.7", "198.51.100.23", "203.0.113.66"]
SPRAY_USERS = ["admin", "root", "oracle", "postgres", "git", "jenkins",
               "backup", "test"]


def _ts() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def _line(program: str, message: str, pid: int = None) -> str:
    pid_s = f"[{pid}]" if pid else ""
    return f"{_ts()} web05 {program}{pid_s}: {message}"


def benign(write) -> None:
    u = random.choice(BENIGN_USERS)
    ip = random.choice(BENIGN_IPS)
    write(_line("sshd", f"Accepted password for {u} from {ip} port "
                        f"{random.randint(40000, 60000)} ssh2", random.randint(2000, 9000)))


def brute_force(write) -> None:
    ip = random.choice(ATTACKER_IPS)
    for _ in range(7):
        write(_line("sshd", f"Failed password for root from {ip} port "
                            f"{random.randint(50000, 60000)} ssh2", random.randint(2000, 9000)))
        time.sleep(0.2)


def password_spray(write) -> None:
    ip = "198.51.100.23"
    for u in SPRAY_USERS:
        write(_line("sshd", f"Failed password for {u} from {ip} port "
                            f"{random.randint(50000, 60000)} ssh2", random.randint(2000, 9000)))
        time.sleep(0.2)


def port_scan(write) -> None:
    ip = "203.0.113.66"
    for port in range(9200, 9225):
        write(_line("honeypot", f"TCP connection from {ip} to port {port}",
                    random.randint(2000, 9000)))
        time.sleep(0.05)


def root_account(write) -> None:
    write(_line("useradd", "new user: name=svc-evil, UID=0, GID=0, "
                           "home=/home/svc-evil, shell=/bin/bash", 5000))


ATTACKS = [brute_force, password_spray, port_scan, root_account]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="logs/live.log")
    ap.add_argument("--attack-every", type=float, default=15.0,
                    help="seconds between attack bursts")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="stop after N seconds (0 = run forever)")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    def write(line: str) -> None:
        with out.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    attacks = itertools.cycle(ATTACKS)
    start = time.time()
    last_attack = 0.0
    print(f"● generating live traffic -> {out} (attack every {args.attack_every}s)",
          flush=True)
    while True:
        if args.duration and time.time() - start > args.duration:
            break
        benign(write)
        now = time.time()
        if now - last_attack >= args.attack_every:
            atk = next(attacks)
            print(f"  ⚔ injecting: {atk.__name__}", flush=True)
            atk(write)
            last_attack = now
        time.sleep(random.uniform(1.0, 2.5))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
