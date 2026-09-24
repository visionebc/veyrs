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

export VEYRS_ENVIRONMENT=development
# The suite makes hundreds of calls from one client identity. The limiter
# itself is covered by tests/test_phase10_hardening.py, which instantiates
# the middleware directly with a small limit.
export VEYRS_RATE_LIMIT_PER_MINUTE=100000
export VEYRS_AUTH_RATE_LIMIT_PER_MINUTE=100000
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

exec venv/bin/python -m pytest "$@"
