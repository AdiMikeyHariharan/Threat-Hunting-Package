"""Generate the syslog sample datasets in sample_data/ (deterministic, seeded).

Each dataset is a realistic day of activity with a planted attack, written so
the attack steps trip the syslog rules in ``rules/`` while normal activity
(staff logins, CI deploys, cron, typos, routine sudo) stays quiet:

  auth.log           Quick-start: SSH brute force -> root login -> backdoor
                     account on one web server, inside a normal working day.
  enterprise_sim.log Identity attacks across an estate: password spraying,
                     distributed credential stuffing, an off-hours root login
                     from the jump host, and a contractor insider chain.
  attack_sim.log     Full overnight intrusion kill chain: scan, spray, stuffing,
                     brute force, root, UID-0 persistence, sudo shell, firewall
                     off, lateral movement.

portscan.log is not generated here: scripts/simulate_scan.py records a real
nmap scan instead.

    python scripts/generate_sample_logs.py              # all three
    python scripts/generate_sample_logs.py auth.log     # just one
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "sample_data"


class SyslogDay:
    """Collects syslog lines for one day, then writes them in time order."""

    def __init__(self, day: datetime, seed: int, pid_base: dict[str, int]):
        self.day = day
        self.rng = random.Random(seed)
        self.pids = dict(pid_base)
        self.lines: list[tuple[datetime, str]] = []

    def at(self, hh: int, mm: int, ss: int = 0) -> datetime:
        return self.day.replace(hour=hh, minute=mm, second=ss)

    def port(self) -> int:
        return self.rng.randint(40000, 61000)

    def next_pid(self, host: str) -> int:
        self.pids[host] += self.rng.randint(1, 9)
        return self.pids[host]

    def emit(self, ts: datetime, host: str, program: str, message: str, pid: int | None = None) -> None:
        if pid is None:
            pid = self.next_pid(host)
        tag = f"{program}[{pid}]" if pid else program
        self.lines.append((ts, f"{ts:%b %d %H:%M:%S} {host} {tag}: {message}"))

    def ssh_login(self, ts: datetime, host: str, user: str, ip: str, method: str = "password") -> None:
        pid = self.next_pid(host)
        self.emit(ts, host, "sshd", f"Accepted {method} for {user} from {ip} port {self.port()} ssh2", pid)
        self.emit(ts, host, "sshd", f"pam_unix(sshd:session): session opened for user {user} by (uid=0)", pid)

    def ssh_logout(self, ts: datetime, host: str, user: str) -> None:
        self.emit(ts, host, "sshd", f"pam_unix(sshd:session): session closed for user {user}")

    def failed(self, ts: datetime, host: str, user: str, ip: str, invalid: bool = False) -> None:
        """One failed SSH attempt; invalid users log both sshd lines on one connection."""
        pid, src_port = self.next_pid(host), self.port()
        if invalid:
            self.emit(ts, host, "sshd", f"Invalid user {user} from {ip} port {src_port}", pid)
            self.emit(ts + timedelta(seconds=1), host, "sshd",
                      f"Failed password for invalid user {user} from {ip} port {src_port} ssh2", pid)
        else:
            self.emit(ts, host, "sshd", f"Failed password for {user} from {ip} port {src_port} ssh2", pid)

    def sudo(self, ts: datetime, host: str, user: str, command: str, cwd: str, tty: str) -> None:
        self.emit(ts, host, "sudo", f"  {user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={command}", pid=0)

    def workday(self, host: str, staff: dict[str, str], typo_user: str | None = None) -> None:
        """Morning and afternoon sessions for each staff member."""
        for user, ip in staff.items():
            start = self.at(8, 30) + timedelta(minutes=self.rng.randint(0, 45), seconds=self.rng.randint(0, 59))
            if user == typo_user:                          # one honest typo, then success
                self.failed(start - timedelta(seconds=9), host, user, ip)
            self.ssh_login(start, host, user, ip)
            self.ssh_logout(start + timedelta(hours=self.rng.randint(3, 4), minutes=self.rng.randint(0, 59)), host, user)
            back = self.at(13, 30) + timedelta(minutes=self.rng.randint(0, 40), seconds=self.rng.randint(0, 59))
            self.ssh_login(back, host, user, ip)
            self.ssh_logout(back + timedelta(hours=3, minutes=self.rng.randint(0, 59)), host, user)

    def cron(self, hosts: tuple[str, ...]) -> None:
        for host in hosts:
            for hour in range(24):
                self.emit(self.at(hour, 17), host, "CRON", "(root) CMD (cd / && run-parts --report /etc/cron.hourly)")

    def deploys(self, host: str, runner_ip: str, hours: tuple[int, ...]) -> None:
        for hour in hours:
            ts = self.at(hour, 5, self.rng.randint(0, 59))
            self.ssh_login(ts, host, "deploy", runner_ip, method="publickey")
            self.ssh_logout(ts + timedelta(seconds=self.rng.randint(20, 90)), host, "deploy")

    def write(self, name: str) -> Path:
        self.lines.sort(key=lambda item: item[0])
        out = SAMPLE_DIR / name
        out.write_text("\n".join(text for _, text in self.lines) + "\n", encoding="utf-8")
        print(f"Wrote {len(self.lines)} lines to {out}")
        return out


# --------------------------------------------------------------------------- #
# auth.log - quick-start: brute force to backdoor on web01                     #
# --------------------------------------------------------------------------- #
def auth() -> Path:
    """Expected: SSH-BRUTE-0001, SSH-INVALID-USER-0001, SSH-ROOT-LOGIN-0001,
    NEW-ACCOUNT-0001, SUDO-ABUSE-0001, ANOMALY-VOLUME-0001."""
    d = SyslogDay(datetime(2026, 3, 10), seed=310, pid_base={"web01": 1800})
    attacker = "45.83.19.7"
    staff = {"alice": "10.0.4.21", "bob": "10.0.4.55", "carol": "10.0.4.38", "dave": "10.0.4.62"}

    d.cron(("web01",))
    d.deploys("web01", "10.0.4.10", hours=(9, 12, 16))
    d.workday("web01", staff, typo_user="carol")
    d.sudo(d.at(9, 3, 44), "web01", "alice", "/usr/bin/apt update", "/home/alice", "pts/0")
    d.sudo(d.at(11, 20, 5), "web01", "dave", "/usr/bin/systemctl reload nginx", "/home/dave", "pts/2")

    # The attack (business hours, so the off-hours rule stays quiet).
    t = d.at(13, 57, 55)
    for _ in range(6):                                     # fast root brute force
        d.failed(t, "web01", "root", attacker)
        t += timedelta(seconds=2)
    d.failed(t, "web01", "admin", attacker)
    for user in ("oracle", "postgres"):
        t += timedelta(seconds=2)
        d.failed(t, "web01", user, attacker, invalid=True)
    d.ssh_login(d.at(13, 58, 40), "web01", "root", attacker)
    d.emit(d.at(13, 59, 10), "web01", "useradd",
           "new user: name=svc-backup, UID=1050, GID=1050, home=/home/svc-backup, shell=/bin/bash")
    d.ssh_logout(d.at(14, 1, 3), "web01", "root")

    # bob mistypes his sudo password three times: a real (if benign) alert to triage.
    d.emit(d.at(14, 44, 2), "web01", "sudo",
           "   bob : 3 incorrect password attempts ; authentication failure ; TTY=pts/1 ; USER=root", pid=0)
    return d.write("auth.log")


# --------------------------------------------------------------------------- #
# enterprise_sim.log - identity attacks across the estate                      #
# --------------------------------------------------------------------------- #
def enterprise_sim() -> Path:
    """Expected: PWD-SPRAY-0001, CRED-STUFF-0001, SSH-ROOT-LOGIN-0001,
    OFFHOURS-ROOT-0001, PRIVGRP-0001, SUDO-ROOT-SHELL-0001, FW-DISABLE-0001,
    PASSWD-CHANGE-0001, ROOT-ACCOUNT-0001, NEW-ACCOUNT-0001, ANOMALY-VOLUME-0001."""
    d = SyslogDay(datetime(2026, 7, 5), seed=705,
                  pid_base={"web05": 5000, "app02": 6100, "jump01": 4200, "db03": 8300})
    sprayer = "198.51.100.23"
    stuffers = [f"203.0.113.{n}" for n in range(10, 22)]
    jump_ip = "10.0.5.9"
    staff = {"alice": "10.0.5.31", "bob": "10.0.5.32", "carol": "10.0.5.33", "dave": "10.0.5.34",
             "erin": "10.0.5.35", "frank": "10.0.5.36", "grace": "10.0.5.37", "henry": "10.0.5.38"}

    d.cron(("web05", "app02", "db03"))
    d.deploys("web05", "10.0.5.20", hours=(2, 10, 15))
    d.deploys("app02", "10.0.5.20", hours=(10, 15))
    d.workday("web05", dict(list(staff.items())[:5]), typo_user="erin")
    d.workday("app02", dict(list(staff.items())[5:]))
    d.ssh_login(d.at(9, 40, 12), "jump01", "dave", staff["dave"])
    d.ssh_logout(d.at(17, 2, 40), "jump01", "dave")

    # 03:12 - someone uses the jump host to log in to db03 as root, off hours.
    d.ssh_login(d.at(3, 12, 0), "db03", "root", jump_ip)
    d.ssh_logout(d.at(3, 40, 18), "db03", "root")

    # 13:00 - password spraying: one guess per staff account, paced ~35 s apart.
    t = d.at(13, 0, 0)
    for user in list(staff) + ["admin", "backupsvc"]:
        d.failed(t, "web05", user, sprayer)
        t += timedelta(seconds=d.rng.randint(32, 38))

    # 13:10 - distributed credential stuffing: 12 hosts, one guess each, against "admin".
    t = d.at(13, 10, 0)
    for ip in stuffers:
        d.failed(t, "web05", "admin", ip)
        t += timedelta(seconds=d.rng.randint(40, 55))

    # 14:00 - insider: a contractor account is granted sudo and abuses it.
    d.ssh_login(d.at(13, 55, 20), "app02", "contractor", "10.0.5.77")
    d.emit(d.at(14, 0, 0), "app02", "usermod", "add 'contractor' to group 'sudo'")
    d.sudo(d.at(14, 5, 0), "app02", "contractor", "/bin/bash", "/home/contractor", "pts/3")
    d.sudo(d.at(14, 6, 0), "app02", "contractor", "/usr/sbin/ufw disable", "/root", "pts/3")
    d.emit(d.at(14, 7, 0), "app02", "passwd", "pam_unix(passwd:chauthtok): password changed for backupsvc")
    d.emit(d.at(14, 8, 30), "app02", "useradd",
           "new user: name=support, UID=0, GID=0, home=/home/support, shell=/bin/bash, from=/dev/pts/3")
    d.ssh_logout(d.at(14, 20, 11), "app02", "contractor")
    return d.write("enterprise_sim.log")


# --------------------------------------------------------------------------- #
# attack_sim.log - overnight intrusion kill chain                              #
# --------------------------------------------------------------------------- #
def attack_sim() -> Path:
    """Expected: PORT-SCAN-0001, PWD-SPRAY-0001, SSH-INVALID-USER-0001,
    CRED-STUFF-0001, SSH-BRUTE-0001, SSH-ROOT-LOGIN-0001, OFFHOURS-ROOT-0001,
    NEW-ACCOUNT-0001 (incl. one benign), ROOT-ACCOUNT-0001, PASSWD-CHANGE-0001,
    PRIVGRP-0001, SUDO-ABUSE-0001, SUDO-ROOT-SHELL-0001, FW-DISABLE-0001,
    ANOMALY-VOLUME-0001."""
    d = SyslogDay(datetime(2026, 7, 5), seed=1337,
                  pid_base={"web02": 3000, "db01": 7000, "sensor01": 9000})
    attacker = "203.0.113.66"
    botnet = [f"198.51.100.{n}" for n in range(10, 22)]
    web02_internal = "10.0.7.20"
    staff = {"alice": "10.0.7.31", "bob": "10.0.7.44", "carol": "10.0.7.58", "dave": "10.0.7.62"}

    d.cron(("web02", "db01"))
    d.emit(d.at(3, 30), "db01", "CRON", "(postgres) CMD (/usr/local/bin/pg_backup.sh --nightly)")
    d.deploys("web02", "10.0.7.12", hours=(0, 4, 9, 11, 14, 16))

    # 1. Recon: port scan of the edge sensor.
    start = d.at(1, 58, 3)
    for i, p in enumerate(d.rng.sample([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                                        995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080], 20)):
        d.emit(start + timedelta(milliseconds=250 * i), "sensor01", "honeypot",
               f"TCP connection from {attacker} to port {p}", pid=9001)

    # 2. Password spraying, paced to stay under the brute-force rule.
    t = d.at(2, 2, 10)
    real_accounts = set(staff) | {"deploy", "root"}
    for user in ["admin", "oracle", "postgres", "test", "ubuntu", "git", "jenkins", "ftp", "guest", "alice"]:
        d.failed(t, "web02", user, attacker, invalid=user not in real_accounts)
        t += timedelta(seconds=d.rng.randint(19, 26))

    # 3. Distributed credential stuffing against bob.
    t = d.at(2, 7, 0)
    for ip in botnet:
        d.failed(t, "web02", "bob", ip)
        t += timedelta(seconds=d.rng.randint(15, 30))

    # 4. Root brute force, 5. off-hours root login.
    t = d.at(2, 13, 2)
    for _ in range(7):
        d.failed(t, "web02", "root", attacker)
        t += timedelta(seconds=d.rng.randint(2, 4))
    d.ssh_login(d.at(2, 14, 1), "web02", "root", attacker)

    # 6. Persistence: hidden root-equivalent account.
    d.emit(d.at(2, 15, 10), "web02", "useradd",
           "new user: name=svc-update, UID=0, GID=0, home=/var/lib/svc-update, shell=/bin/bash, from=/dev/pts/2")
    d.emit(d.at(2, 15, 24), "web02", "passwd", "pam_unix(passwd:chauthtok): password changed for svc-update")
    d.emit(d.at(2, 15, 40), "web02", "usermod", "add 'svc-update' to group 'sudo'")
    d.emit(d.at(2, 15, 41), "web02", "usermod", "add 'svc-update' to shadow group 'sudo'")
    d.ssh_logout(d.at(2, 16, 5), "web02", "root")

    # 7. Privilege escalation, 8. defense evasion.
    d.ssh_login(d.at(2, 17, 12), "web02", "svc-update", attacker)
    d.emit(d.at(2, 17, 40), "web02", "sudo",
           "pam_unix(sudo:auth): authentication failure; logname=svc-update uid=0 euid=0 tty=/dev/pts/3 "
           "ruser=svc-update rhost=  user=svc-update")
    home = "/var/lib/svc-update"
    d.sudo(d.at(2, 17, 52), "web02", "svc-update", "/bin/bash", home, "pts/3")
    d.sudo(d.at(2, 19, 5), "web02", "svc-update", "/usr/sbin/ufw disable", home, "pts/3")
    d.sudo(d.at(2, 19, 9), "web02", "svc-update", "/usr/sbin/iptables -F", home, "pts/3")

    # 9. Lateral movement web02 -> db01.
    d.ssh_login(d.at(2, 22, 30), "db01", "root", web02_internal)
    d.emit(d.at(2, 23, 2), "db01", "passwd", "pam_unix(passwd:chauthtok): password changed for postgres")
    d.ssh_logout(d.at(2, 31, 44), "db01", "root")
    d.ssh_logout(d.at(2, 32, 10), "web02", "svc-update")

    # Normal working day; dave (admin) does routine sudo and one benign new account.
    d.workday("web02", staff, typo_user="bob")
    d.sudo(d.at(10, 12, 4), "web02", "dave", "/usr/bin/systemctl restart nginx", "/home/dave", "pts/1")
    d.sudo(d.at(10, 40, 31), "web02", "dave", "/usr/bin/apt-get upgrade -y", "/home/dave", "pts/1")
    d.sudo(d.at(15, 2, 47), "web02", "dave", "/usr/sbin/useradd -m intern1", "/home/dave", "pts/1")
    d.emit(d.at(15, 2, 47), "web02", "useradd",
           "new user: name=intern1, UID=1005, GID=1005, home=/home/intern1, shell=/bin/bash, from=/dev/pts/1")
    d.ssh_login(d.at(11, 3, 15), "db01", "carol", staff["carol"])
    d.ssh_logout(d.at(11, 48, 2), "db01", "carol")
    return d.write("attack_sim.log")


DATASETS = {"auth.log": auth, "enterprise_sim.log": enterprise_sim, "attack_sim.log": attack_sim}

if __name__ == "__main__":
    for name in sys.argv[1:] or DATASETS:
        DATASETS[name]()
