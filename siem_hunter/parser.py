"""Log parsing / normalisation.

A SIEM cannot match rules against free text — it first normalises each line
into typed fields. This module mirrors that stage for two common formats:

  * Linux ``auth.log`` (syslog) lines, and
  * generic JSON lines (one object per line).

Extending the parser to a new source means adding one function and registering
it; rules never change.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Iterable
from datetime import datetime, timezone

from .logging_config import get_logger
from .models import Event

log = get_logger(__name__)

# "Mar 10 13:58:01 web01 sshd[2101]: Failed password for root from 10.0.0.9 port 55234 ssh2"
_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Sub-patterns that pull structured fields out of common auth messages.
_MESSAGE_EXTRACTORS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from "
               r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Accepted password for (?P<user>\S+) from "
               r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Accepted publickey for (?P<user>\S+) from "
               r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"session opened for user (?P<user>\S+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"),
    # Network sensor / honeypot connection log (used for port-scan detection).
    re.compile(r"connection from (?P<src_ip>\d+\.\d+\.\d+\.\d+) to port "
               r"(?P<dst_port>\d+)"),
]


def _parse_syslog_timestamp(raw_ts: str, assume_year: int) -> datetime:
    """Syslog omits the year; assume the supplied one and normalise to UTC."""
    dt = datetime.strptime(f"{assume_year} {raw_ts}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def parse_syslog_line(line: str, source: str, assume_year: int) -> Event | None:
    m = _SYSLOG_RE.match(line)
    if not m:
        log.debug("syslog_parse_miss", source=source, line=line[:120])
        return None

    fields = {
        "host": m.group("host"),
        "program": m.group("program"),
        "message": m.group("message"),
    }
    if m.group("pid"):
        fields["pid"] = int(m.group("pid"))

    for extractor in _MESSAGE_EXTRACTORS:
        em = extractor.search(m.group("message"))
        if em:
            fields.update({k: v for k, v in em.groupdict().items() if v})
            break

    ts = _parse_syslog_timestamp(m.group("ts"), assume_year)
    fields["hour"] = ts.hour           # derived field for time-of-day rules
    return Event(timestamp=ts, source=source, raw=line, fields=fields)


def parse_json_line(line: str, source: str) -> Event | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        log.debug("json_parse_miss", source=source, line=line[:120])
        return None

    ts_raw = obj.pop("timestamp", None) or obj.pop("@timestamp", None)
    if ts_raw:
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    obj.setdefault("hour", ts.hour)    # derived field for time-of-day rules
    return Event(timestamp=ts, source=source, raw=line, fields=obj)


def parse_lines(
    lines: Iterable[str],
    source: str,
    fmt: str = "syslog",
    assume_year: int | None = None,
) -> Iterator[Event]:
    """Parse an iterable of raw lines into :class:`Event` objects.

    Unparseable / blank lines are skipped (and logged at DEBUG). A running
    count is emitted at the end so ingestion health is visible.
    """
    assume_year = assume_year or datetime.now(timezone.utc).year
    parsed = skipped = 0

    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue

        if fmt == "syslog":
            event = parse_syslog_line(line, source, assume_year)
        elif fmt == "json":
            event = parse_json_line(line, source)
        else:
            raise ValueError(f"unknown format: {fmt!r}")

        if event is None:
            skipped += 1
            continue
        parsed += 1
        yield event

    log.info("ingestion_complete", source=source, format=fmt,
             parsed=parsed, skipped=skipped)
