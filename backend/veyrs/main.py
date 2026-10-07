"""VEYRS ASGI application.

Composition root: middleware, error handling, observability and the versioned
API router. Nothing business-logical lives here.
"""
from __future__ import annotations

import logging
import secrets
import time
import uuid

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .api.v1 import api_router
from .config import settings
from .db import engine
from .security.ratelimit import RateLimitMiddleware
from .observability import (
    RequestContextMiddleware,
    metrics_response,
    setup_logging,
)

setup_logging()
log = logging.getLogger("veyrs")

DESCRIPTION = """
**VEYRS** - Unified Cybersecurity Risk Management.

Connects assets, vulnerabilities, threat intelligence, risk, ownership, tickets,
SLA, escalation, remediation, verification, compliance and audit into one graph.

Authentication: `Authorization: Bearer <access token>` or `X-API-Key: veyrs_...`.
Every endpoint authorizes server-side; nothing is enforced only in the UI.
"""


@asynccontextmanager
async def lifespan(instance: FastAPI):
    log.info(
        "veyrs starting version=%s env=%s debug=%s",
        settings.version, settings.environment, settings.debug,
    )
    instance.state.started_at = time.time()
    yield
    log.info("veyrs shutting down")


def create_app() -> FastAPI:
    if settings.is_production:
        settings.assert_production_safe()

    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version=settings.version,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
        lifespan=lifespan,
    )

    # Order matters: Starlette runs middleware outside-in, so the rate limiter
    # added AFTER RequestContextMiddleware runs INSIDE it -- a 429 still gets a
    # correlation id and security headers.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "Accept-Language",
                       "X-Correlation-ID"],
        max_age=600,
    )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.get("/healthz", tags=["operations"], summary="Liveness probe")
    def healthz() -> dict:
        return {"status": "ok", "app": settings.app_name, "version": settings.version}

    @app.get("/readyz", tags=["operations"], summary="Readiness probe")
    def readyz() -> JSONResponse:
        checks: dict[str, str] = {}
        code = status.HTTP_200_OK
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except SQLAlchemyError as exc:
            checks["database"] = f"error: {type(exc).__name__}"
            code = status.HTTP_503_SERVICE_UNAVAILABLE
        try:
            import redis  # local import keeps redis optional at import time

            redis.Redis.from_url(settings.redis_url, socket_timeout=2).ping()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"error: {type(exc).__name__}"
            code = status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse({"status": "ok" if code == 200 else "degraded", "checks": checks},
                            status_code=code)

    @app.get("/metrics", tags=["operations"], include_in_schema=False)
    def metrics(request: Request):
        """Prometheus scrape target. Authenticated, because it is not public data.

        The exposition enumerates every route template, the build version and
        the traffic volume per endpoint - a map of the attack surface for
        anyone who can read it. The nginx `allow 10.0.0.0/24` in front of this
        is NOT the control it looks like: every request arrives from the fleet
        reverse proxy, whose address is inside that range, so the allowlist
        matches on the proxy rather than on the caller.

        An unauthenticated caller gets 404, not 401: a probe learns nothing
        about whether the endpoint exists or the token was merely wrong.
        """
        token = settings.metrics_token
        if not token:
            # Refusing in production is the safe default; leaving it open in
            # development keeps `curl localhost:8000/metrics` usable.
            if settings.is_production:
                raise HTTPException(status_code=404, detail="Not Found")
            return metrics_response()
        supplied = request.headers.get("Authorization", "")
        if not secrets.compare_digest(supplied, f"Bearer {token}"):
            raise HTTPException(status_code=404, detail="Not Found")
        return metrics_response()

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        # Echo the field errors but never the submitted values - request bodies
        # in this product routinely carry vulnerability detail and credentials.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_error",
                "detail": [
                    {"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")}
                    for e in exc.errors()
                ],
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def _db_handler(request: Request, exc: SQLAlchemyError):
        cid = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        log.exception("database error correlation_id=%s", cid)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "correlation_id": cid},
        )

    return app


app = create_app()
