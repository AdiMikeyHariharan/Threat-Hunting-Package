"""Structured logging setup for the whole pipeline.

The faculty requirement is "extensive and proper logging". In a SIEM the logs
are the product, so we treat our own telemetry the same way we treat ingested
events: structured, timestamped, and machine-parseable.

Design choices
--------------
* JSON to a rotating file  -> durable, greppable, ingestable by a real SIEM.
* Human-readable to console -> comfortable during development / demo.
* A run-scoped ``run_id``   -> every log line for one pipeline invocation
                               shares an id so a whole run can be correlated.
* ISO-8601 UTC timestamps, log level, module, and the calling function are
  bound automatically.

Call :func:`configure_logging` once at start-up, then obtain loggers with
:func:`get_logger`.
"""

from __future__ import annotations

import logging
import logging.handlers
import uuid
from pathlib import Path

import structlog

# A single id per process run; bound to every record so one run is greppable.
RUN_ID = uuid.uuid4().hex[:12]


def configure_logging(
    log_dir: str | Path = "logs",
    level: str = "INFO",
    json_file: str = "siem_hunter.jsonl",
    console: bool = True,
) -> None:
    """Configure structlog + stdlib logging for the process.

    Parameters
    ----------
    log_dir:
        Directory that will hold the rotating JSON log file.
    level:
        Minimum level to emit (``DEBUG``/``INFO``/``WARNING``/...).
    json_file:
        Filename for the structured JSON log (one JSON object per line).
    console:
        Also emit colourised, human-readable logs to stderr.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Processors shared by every record before it is handed to a renderer.
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.CallsiteParameterAdder(
            {
                structlog.processors.CallsiteParameter.MODULE,
                structlog.processors.CallsiteParameter.FUNC_NAME,
            }
        ),
    ]

    structlog.configure(
        processors=shared_processors
        + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        cache_logger_on_first_use=True,
    )

    # Rotating JSON file: 5 MB per file, keep 5 backups.
    json_handler = logging.handlers.RotatingFileHandler(
        log_path / json_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    json_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared_processors,
            processor=structlog.processors.JSONRenderer(),
        )
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(numeric_level)
    root.addHandler(json_handler)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            structlog.stdlib.ProcessorFormatter(
                foreign_pre_chain=shared_processors,
                processor=structlog.dev.ConsoleRenderer(colors=True),
            )
        )
        root.addHandler(console_handler)

    # Bind the run id to every subsequent log line in this process.
    structlog.contextvars.bind_contextvars(run_id=RUN_ID)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger namespaced by ``name`` (usually ``__name__``)."""
    return structlog.get_logger(name)
