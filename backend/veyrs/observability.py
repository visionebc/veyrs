"""Structured logging, correlation IDs, security headers and Prometheus metrics.

Deliberately dependency-free: no prometheus_client, no OpenTelemetry SDK at this
stage. `/metrics` emits valid Prometheus text format from an in-process counter
map, and every log line is JSON so Loki/Promtail can index it without regex.
OTel export is a drop-in later (see docs/ADRs/0007-observability.md).

Three properties this module must keep, all learned the hard way:

* **Callers never format a label.** `incr()` takes a mapping and escapes the
  values itself. A request path is attacker-controlled, and an unescaped quote
  in one emits a line no scraper can parse - which silently drops *every*
  metric for the target, not just the poisoned series.
* **The label space is bounded.** Recording an unrouted request path as a label
  value turns the registry into a memory leak with a URL bar attached: 404s are
  free to generate and each one minted a new series.
* **The reading is per worker.** The app runs with several uvicorn workers and
  this registry lives in one process, so a scrape samples whichever worker
  answered. `veyrs_build_info` carries the pid to make that visible rather than
  quietly wrong.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # The SPA is served by nginx with the same policy; keeping it on API
    # responses too means an accidental HTML response can't run inline script.
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field in ("correlation_id", "org_id", "actor", "path", "method", "status",
                      "duration_ms"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for noisy in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# --- metrics --------------------------------------------------------------

_lock = threading.Lock()
_counters: dict[tuple[str, str], int] = defaultdict(int)
_histogram: dict[str, list[float]] = defaultdict(list)
_series: dict[str, int] = defaultdict(int)

#: Ceiling on distinct label combinations per metric name. Past it, every new
#: combination collapses into one `overflow` series: the traffic is still
#: counted, the registry stops growing.
MAX_SERIES_PER_METRIC = 256

#: Label value for a request that matched no route. The raw path must NEVER be
#: used there - see the module docstring.
UNMATCHED_PATH = "<unmatched>"

#: Escapes required by the Prometheus text format for a label VALUE.
_LABEL_ESCAPES = str.maketrans({"\\": "\\\\", '"': '\\"', "\n": "\\n"})


def _render_labels(labels: dict[str, object]) -> str:
    """Render a label mapping, escaping every value. Sorted for stable keys."""
    return ",".join(
        f'{name}="{str(value).translate(_LABEL_ESCAPES)}"'
        for name, value in sorted(labels.items())
        if value is not None
    )


def incr(metric: str, labels: dict[str, object] | None = None, by: int = 1) -> None:
    """Add to a counter.

    `labels` is a mapping, not a pre-formatted string, so a caller cannot skip
    escaping. Series count is capped per metric name.
    """
    rendered = _render_labels(labels or {})
    with _lock:
        key = (metric, rendered)
        if key not in _counters and _series[metric] >= MAX_SERIES_PER_METRIC:
            key = (metric, 'overflow="1"')
        if key not in _counters:
            _series[metric] += 1
        _counters[key] += by


def observe(metric: str, value: float) -> None:
    with _lock:
        bucket = _histogram[metric]
        bucket.append(value)
        if len(bucket) > 5000:  # bounded memory; percentiles stay representative
            del bucket[: len(bucket) - 5000]


def reset_metrics() -> None:
    """Drop every series. For tests, and for clearing a polluted registry."""
    with _lock:
        _counters.clear()
        _histogram.clear()
        _series.clear()


def metrics_response() -> Response:
    from .config import settings

    build_labels = _render_labels({
        "version": settings.version,
        "env": settings.environment,
        # The registry is per process; naming the worker keeps a scrape honest.
        "worker": os.getpid(),
    })
    lines = [
        "# HELP veyrs_build_info Static build information for the answering worker.",
        "# TYPE veyrs_build_info gauge",
        f"veyrs_build_info{{{build_labels}}} 1",
    ]
    with _lock:
        counters = dict(_counters)
        hist = {k: list(v) for k, v in _histogram.items()}
        series = dict(_series)

    lines += [
        "# HELP veyrs_metrics_series Distinct label sets held per metric name.",
        "# TYPE veyrs_metrics_series gauge",
    ]
    for metric, count in sorted(series.items()):
        lines.append(f'veyrs_metrics_series{{{_render_labels({"metric": metric})}}} {count}')

    # One TYPE line per metric NAME. Emitting a hardcoded name here declared a
    # type for a metric that might not exist and left any other counter untyped.
    emitted: set[str] = set()
    for (metric, labels), value in sorted(counters.items()):
        if metric not in emitted:
            lines.append(f"# TYPE {metric} counter")
            emitted.add(metric)
        label_part = f"{{{labels}}}" if labels else ""
        lines.append(f"{metric}{label_part} {value}")

    for metric, values in sorted(hist.items()):
        if not values:
            continue
        ordered = sorted(values)
        lines += [
            f"# TYPE {metric} summary",
            f"{metric}_count {len(ordered)}",
            f"{metric}_sum {sum(ordered):.3f}",
            f'{metric}{{quantile="0.5"}} {ordered[len(ordered) // 2]:.3f}',
            f'{metric}{{quantile="0.95"}} {ordered[int(len(ordered) * 0.95)]:.3f}',
            f'{metric}{{quantile="0.99"}} {ordered[int(len(ordered) * 0.99)]:.3f}',
        ]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Correlation ID + timing + security headers on every response."""

    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Same label set as the success path: a series that appears and
            # disappears with a label missing is a broken time series.
            incr("veyrs_requests_total", {"method": request.method, "status": 500,
                                          "path": UNMATCHED_PATH})
            logging.getLogger("veyrs.request").exception(
                "unhandled error", extra={"correlation_id": correlation_id,
                                          "path": request.url.path,
                                          "method": request.method}
            )
            raise
        duration_ms = (time.perf_counter() - started) * 1000
        # A matched route contributes its TEMPLATE ("/api/v1/findings/{id}"), a
        # closed set. An unmatched request contributes a constant: its path is
        # whatever the caller typed, and 404s cost an attacker nothing.
        route = request.scope.get("route")
        path_label = getattr(route, "path", None) or UNMATCHED_PATH
        incr(
            "veyrs_requests_total",
            {"method": request.method, "status": response.status_code, "path": path_label},
        )
        observe("veyrs_request_duration_ms", duration_ms)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Response-Time-ms"] = f"{duration_ms:.1f}"
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        principal = getattr(request.state, "principal", None)
        logging.getLogger("veyrs.request").info(
            "request",
            extra={
                "correlation_id": correlation_id,
                "path": request.url.path,
                "method": request.method,
                "status": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "org_id": str(principal.organization_id) if principal else None,
                "actor": principal.label if principal else None,
            },
        )
        return response
