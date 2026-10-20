"""Log parsing / normalisation.

A SIEM cannot match rules against free text — it first normalises each line
into typed fields. This module mirrors that stage for three common formats:

  * Linux ``auth.log`` (syslog) lines,
  * generic JSON lines (one object per line), and
  * tabular files — CSV (``.csv``) and Excel (``.xlsx``/``.xls``) spreadsheets,
    where every row becomes one Event and every column becomes a field.

Extending the parser to a new source means adding one function and registering
it; rules never change.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import pandas as pd
    _PANDAS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PANDAS_AVAILABLE = False

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

    try:
        ts = _parse_syslog_timestamp(m.group("ts"), assume_year)
    except ValueError:
        log.debug("syslog_timestamp_invalid", source=source, line=line[:120])
        return None
    fields["hour"] = ts.hour           # derived field for time-of-day rules
    return Event(timestamp=ts, source=source, raw=line, fields=fields)


def parse_json_line(line: str, source: str) -> Event | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        log.debug("json_parse_miss", source=source, line=line[:120])
        return None

    if not isinstance(obj, dict):
        log.debug("json_object_expected", source=source, line=line[:120])
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
    else:
        ts = ts.astimezone(timezone.utc)

    # Normalise gateway and cloud access log fields to standard SIEM schema
    if "client_ip" in obj and "src_ip" not in obj:
        obj["src_ip"] = obj["client_ip"]
    if "subject" in obj and "user" not in obj:
        obj["user"] = obj["subject"]

    obj.setdefault("hour", ts.hour)    # derived field for time-of-day rules
    return Event(timestamp=ts, source=source, raw=line, fields=obj)


# Common column name variants that represent a timestamp in tabular data.
_TS_COLUMN_CANDIDATES = [
    "timestamp", "@timestamp", "time", "datetime", "date_time",
    "event_time", "eventtime", "log_time", "logtime", "ts",
]


def parse_tabular_file(
    path: str | Path,
    source: str,
) -> Iterator["Event"]:
    """Parse a CSV or Excel file into :class:`Event` objects.

    Every row becomes one event and every column becomes a field.  A timestamp
    column is detected automatically from a list of common name variants; if
    none is found the current UTC time is used for all rows.

    Parameters
    ----------
    path:
        Absolute or relative path to the file.  Extension determines the
        reader: ``.xlsx`` / ``.xls`` → ``pd.read_excel``; everything else
        (including ``.csv``) → ``pd.read_csv``.
    source:
        Label used for logging and the ``Event.source`` field.
    """
    if not _PANDAS_AVAILABLE:
        raise ImportError(
            "pandas is required for CSV/Excel parsing. "
            "Install it with: pip install pandas openpyxl"
        )

    path = Path(path)
    ext = path.suffix.lower()
    if ext in (".xlsx", ".xls"):
        df = pd.read_excel(path, dtype=str)
    else:
        df = pd.read_csv(path, dtype=str)

    # Normalise column names: strip whitespace, lower-case.
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

    # Find the timestamp column (first match wins).
    ts_col: str | None = None
    for candidate in _TS_COLUMN_CANDIDATES:
        if candidate in df.columns:
            ts_col = candidate
            break

    parsed = skipped = 0
    now_utc = datetime.now(timezone.utc)

    for _, row in df.iterrows():
        fields: dict = {k: v for k, v in row.items() if pd.notna(v)}

        # Resolve timestamp.
        if ts_col and ts_col in fields:
            raw_ts = str(fields.pop(ts_col))
            try:
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                try:
                    ts = pd.to_datetime(raw_ts).to_pydatetime()
                except Exception:
                    ts = now_utc
        else:
            ts = now_utc

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)

        fields.setdefault("hour", ts.hour)

        # Build a human-readable raw representation of the row.
        raw_line = ", ".join(f"{k}={v}" for k, v in row.items() if pd.notna(v))

        try:
            yield Event(timestamp=ts, source=source, raw=raw_line, fields=fields)
            parsed += 1
        except Exception as exc:  # pragma: no cover
            log.debug("tabular_row_error", source=source, error=str(exc))
            skipped += 1

    log.info(
        "ingestion_complete",
        source=source,
        format="tabular",
        parsed=parsed,
        skipped=skipped,
    )


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
        elif fmt in ("csv", "xlsx", "xls"):
            # Tabular formats need the full file path, not individual lines.
            # Callers should use parse_tabular_file() directly for these.
            raise ValueError(
                f"format {fmt!r} is tabular — use parse_tabular_file() "
                "instead of parse_lines()."
            )
        else:
            raise ValueError(f"unknown format: {fmt!r}")

        if event is None:
            skipped += 1
            continue
        parsed += 1
        yield event

    log.info("ingestion_complete", source=source, format=fmt,
             parsed=parsed, skipped=skipped)
