#!/bin/sh
# API entrypoint. Mirrors the ExecStart of veyrs-api.service, with the two
# differences a container forces and nothing else.
set -eu

# 1. Bind address. The host unit binds 127.0.0.1 because nginx runs beside it;
#    inside a container 127.0.0.1 is the container itself, so nginx -- which is
#    a different container -- could never reach it. The boundary here is the
#    absence of a published port on this service (compose.yaml, and a test),
#    not the bind address.
HOST="${VEYRS_BIND_HOST:-0.0.0.0}"
PORT="${VEYRS_BIND_PORT:-8000}"

# 2. Workers. uvicorn is asyncio and VEYRS handlers are synchronous
#    SQLAlchemy, so throughput comes from processes. 4 matches the host unit.
#    Raise together with the Postgres pool, not alone.
WORKERS="${VEYRS_WORKERS:-4}"

# Only the console may be believed about who the caller is. Left at the
# default of "trust nobody", uvicorn reports every request as coming from the
# proxy and request.url.scheme is always http; opened to "*", anyone who can
# reach this port can claim any source address. Neither is right, so it is
# pinned to the console's static address on the stack network -- the same
# reasoning that pins it in compose.yaml.
FORWARDED_ALLOW="${VEYRS_FORWARDED_ALLOW_IPS:-127.0.0.1}"

# A secret key that is empty here is NOT a missing default -- config.py mints a
# random one per process. With 4 workers that is 4 different signing keys: a
# token issued by one worker is rejected by the other three, so roughly 3 of
# every 4 authenticated requests fail with an invalid-token error that looks
# like a clock or a cookie problem and moves whenever it is retried. It is
# refused here as well as in compose.yaml because this image is also runnable
# by hand.
if [ -z "${VEYRS_SECRET_KEY:-}" ]; then
    echo "veyrs: VEYRS_SECRET_KEY is empty." >&2
    echo "veyrs: with >1 worker each process would sign tokens with a" >&2
    echo "veyrs: different random key and most requests would fail to" >&2
    echo "veyrs: authenticate intermittently. Refusing to start." >&2
    exit 78   # EX_CONFIG
fi

# Any argument means "run this instead" -- how the init service reuses the
# image, and how an operator gets a shell or runs the CLI:
#   docker compose run --rm api python -m veyrs.cli check
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec uvicorn veyrs.main:app \
    --host "$HOST" --port "$PORT" --workers "$WORKERS" \
    --proxy-headers --forwarded-allow-ips="$FORWARDED_ALLOW" \
    --timeout-keep-alive 30 --no-server-header
