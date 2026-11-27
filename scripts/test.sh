#!/bin/bash
# Canonical VEYRS test entrypoint.
#
# Loads .env (so VEYRS_DATABASE_URL is set), points the suite at the *_test
# database, and runs pytest. Never run bare `pytest` -- conftest needs the
# database URL and would silently fall back to an unusable default.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# Test-only settings live in .env.test (gitignored), NOT in the production .env
# (R-22): the application never reads this file, only the suite does.
#   VEYRS_TEST_DATABASE_URL  a database whose name ends in _test
#   VEYRS_TEST_REDIS_URL     a Redis database that is not 0 (see below)
if [ -f .env.test ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.test
  set +a
fi

export VEYRS_ENVIRONMENT=development
# The suite makes hundreds of calls from one client identity. The limiter
# itself is covered by tests/test_phase10_hardening.py, which instantiates
# the middleware directly with a small limit.
export VEYRS_RATE_LIMIT_PER_MINUTE=100000
export VEYRS_AUTH_RATE_LIMIT_PER_MINUTE=100000

# The node's .env may point at real outbound channels (a mail relay, a chat
# bot). Tests must never reach them: fixture addresses would be handed to a
# live relay, and the notification tests assert the "no relay configured"
# path. A test that needs a channel configures it itself.
export VEYRS_SMTP_HOST=
export VEYRS_NOTIFY_EMAIL_ENABLED=true
export VEYRS_TELEGRAM_BOT_TOKEN=
# Swap ONLY the trailing database name. A naive s|/veyrs|/veyrs_test| would hit
# the "//veyrs:" in the userinfo first and try to log in as veyrs_test.
if [ -z "${VEYRS_TEST_DATABASE_URL:-}" ]; then
  case "${VEYRS_DATABASE_URL:-}" in
    */veyrs)      VEYRS_TEST_DATABASE_URL="${VEYRS_DATABASE_URL%/veyrs}/veyrs_test" ;;
    *_test)       VEYRS_TEST_DATABASE_URL="${VEYRS_DATABASE_URL}" ;;
    # Anything else is NOT known to be a test database. Passing it through is
    # how fixtures reached production once already; conftest refuses a name
    # that does not end in _test, so hand it something that obviously fails
    # rather than something that silently works.
    *)            VEYRS_TEST_DATABASE_URL="${VEYRS_DATABASE_URL:-}" ;;
  esac
fi
export VEYRS_TEST_DATABASE_URL

# The suite deletes the limiter's keys (veyrs:rl:*). Pointing it at the Redis
# that .env names would reset live rate-limit windows on a production node
# (TD-41), so the app is given a TEST Redis instead: database 15 of the local
# server unless VEYRS_TEST_REDIS_URL says otherwise. conftest.py refuses
# database 0 and refuses to run if VEYRS_REDIS_URL differs from this value.
export VEYRS_TEST_REDIS_URL="${VEYRS_TEST_REDIS_URL:-redis://127.0.0.1:6379/15}"
export VEYRS_REDIS_URL="$VEYRS_TEST_REDIS_URL"

exec venv/bin/python -m pytest "$@"
