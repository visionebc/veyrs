#!/usr/bin/env bash
# Assertions against a RUNNING VEYRS container stack.
#
#   docker/veyrs-docker.sh init && docker/veyrs-docker.sh up
#   scripts/test-docker-stack.sh
#
# Deliberately NOT a pytest module: it tests the deployment, not the code, and
# it has to be runnable on a machine that has docker and no Python environment
# for VEYRS. The static guards that CAN run without docker -- "the api service
# never publishes a port", "the Dockerfile never does COPY . ." -- live in
# tests/test_container_stack.py and run in the normal suite.
#
# Every assertion here is a MEASUREMENT. "The stack came up" is not one of
# them: a stack that starts, serves a login form and silently shares one
# database across every tenant also comes up.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENV_FILE="$ROOT/docker/.env"
COMPOSE=(docker compose --project-directory "$ROOT/docker" -f "$ROOT/docker/compose.yaml")

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
note() { printf '        %s\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ -f "$ENV_FILE" ]] || { echo "no $ENV_FILE -- run docker/veyrs-docker.sh init" >&2; exit 2; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
BASE="http://${VEYRS_HTTP_BIND:-127.0.0.1:8080}"

# psql as the SUPERUSER -- used to establish ground truth that the application
# role is not permitted to see. Every "the app cannot read X" assertion is
# paired with a superuser read proving X is actually there; without the pair,
# an empty database passes the isolation test perfectly.
sql_super() { "${COMPOSE[@]}" exec -T postgres psql -U postgres -d "$VEYRS_DB_NAME" -tAc "$1" 2>&1; }
# psql as the APPLICATION role -- subject to row level security.
sql_app() {
    "${COMPOSE[@]}" exec -T -e PGPASSWORD="$VEYRS_DB_PASSWORD" postgres \
        psql -h 127.0.0.1 -U "$VEYRS_DB_USER" -d "$VEYRS_DB_NAME" -tAc "$1" 2>&1
}

# ---------------------------------------------------------------------------
head_ "1. Service surface"

for svc in api postgres redis; do
    ports=$("${COMPOSE[@]}" ps --format '{{.Service}} {{.Ports}}' 2>/dev/null | awk -v s="$svc" '$1==s{$1="";print}')
    # A published port looks like "0.0.0.0:5432->5432/tcp"; an exposed-only one
    # is just "5432/tcp".
    if [[ "$ports" == *"->"* ]]; then
        bad "$svc publishes a host port:$ports"
        note "the api behind a trusted-XFF setting must not be directly reachable,"
        note "or any caller can mint a fresh rate-limit identity per request"
    else
        ok "$svc publishes no host port (${ports:-none})"
    fi
done

if "${COMPOSE[@]}" ps --format '{{.Service}} {{.Ports}}' | grep -q '^console .*->80/tcp'; then
    ok "console is the only published service"
else
    bad "console does not publish :80"
fi

uid=$("${COMPOSE[@]}" exec -T api id -u 2>/dev/null | tr -d '\r')
[[ "$uid" == "10001" ]] && ok "api runs as uid 10001, not root" \
                        || bad "api runs as uid '$uid' (expected 10001)"

# ---------------------------------------------------------------------------
head_ "2. The image carries no secrets"

# The working tree of a real node holds the live signing key, the live Fernet
# key and a production dump. An image layer is additive: a secret copied in
# once cannot be deleted by a later RUN.
#
# SEARCHED, not checked by path. The first version of this asserted that
# /opt/veyrs/.env did not exist -- and a `COPY . .` puts the stack's own
# secrets at /opt/veyrs/docker/.env, one directory over, where that assertion
# never looks. It could not be made to fail by the mutation it exists to
# catch, which is the definition of a test that is not testing anything.
leaked=$("${COMPOSE[@]}" exec -T api sh -c \
    'find /opt/veyrs \( -name ".env" -o -name ".env.*" ! -name ".env.example" \
        -o -name ".bootstrap-credentials" -o -name "*.dump" \) 2>/dev/null' | tr -d '\r')
if [[ -z "$leaked" ]]; then
    ok "no .env / .bootstrap-credentials / *.dump anywhere in the image"
else
    bad "secrets baked into the image:"
    printf '        %s\n' $leaked
fi
if "${COMPOSE[@]}" exec -T api sh -c 'test -d /opt/veyrs/venv' 2>/dev/null; then
    bad "the host venv/ was copied into the image"
else
    ok "host venv/ absent from the image"
fi

# ---------------------------------------------------------------------------
head_ "3. Health and version"

code=$(curl -s -o /tmp/.veyrs-health -w '%{http_code}' "$BASE/healthz")
ver=$(grep -oE '"version":"[^"]+"' /tmp/.veyrs-health 2>/dev/null | cut -d'"' -f4)
declared=$(grep -oE '^version = "[^"]+"' "$ROOT/pyproject.toml" | cut -d'"' -f2)
[[ "$code" == "200" ]] && ok "/healthz 200" || bad "/healthz $code"
[[ -n "$ver" && "$ver" == "$declared" ]] \
    && ok "served version $ver matches pyproject.toml" \
    || bad "served version '$ver' != pyproject.toml '$declared'"

rdy=$(curl -s "$BASE/readyz")
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/readyz")
if [[ "$code" == "200" && "$rdy" == *'"database":"ok"'* && "$rdy" == *'"redis":"ok"'* ]]; then
    ok "/readyz 200 with database ok and redis ok"
else
    bad "/readyz $code -- $rdy"
fi

# ---------------------------------------------------------------------------
head_ "4. The console is actually usable"

idx=$(curl -s "$BASE/")
[[ "$idx" == *"<title>VEYRS Console"* ]] && ok "console index.html served" \
                                        || bad "console index.html not served"

# The failure this catches: on a host install /static/ is an `alias` into the
# DOCUMENTATION site's document root. A console deployed without that second
# site renders every colour as the browser default and looks like a broken
# theme rather than a missing file. Follow the stylesheet the page asks for.
tokens=$(printf '%s' "$idx" | grep -oE '/static/[A-Za-z0-9._-]+\.css' | head -1)
if [[ -n "$tokens" ]]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$tokens")
    [[ "$code" == "200" ]] && ok "$tokens resolves ($code)" \
                           || bad "$tokens is $code -- the console renders unstyled"
else
    bad "index.html references no /static stylesheet"
fi
appjs=$(printf '%s' "$idx" | grep -oE '/?app\.js\?v=[0-9]+' | head -1)
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/${appjs#/}")
[[ "$code" == "200" ]] && ok "${appjs} resolves" || bad "${appjs} is $code"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/metrics")
[[ "$code" == "404" ]] && ok "/metrics is not proxied to the public surface (404)" \
                       || bad "/metrics answered $code through the console"

# Hash routing: an unknown path must still be the single page, not a 404.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/risk-register")
[[ "$code" == "200" ]] && ok "unknown path falls through to index.html" \
                       || bad "unknown path answered $code"

# ---------------------------------------------------------------------------
head_ "5. Authentication really works"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/assets")
[[ "$code" == "401" || "$code" == "403" ]] \
    && ok "API without credentials refused ($code)" \
    || bad "API without credentials answered $code"

login=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"organization\":\"${VEYRS_ADMIN_ORG}\",\"email\":\"${VEYRS_ADMIN_EMAIL}\",\"password\":\"${VEYRS_ADMIN_PASSWORD}\"}")
TOKEN=$(printf '%s' "$login" | grep -oE '"access_token":"[^"]+"' | cut -d'"' -f4)
if [[ -n "$TOKEN" ]]; then
    ok "admin login returned an access token"
    # The reason this is a separate assertion: with an empty VEYRS_SECRET_KEY
    # each of the 4 workers signs with its own random key, so a token minted by
    # one is rejected by the other three. A single login can succeed by luck;
    # replaying the token several times catches the intermittent failure.
    bad_replays=0
    for _ in 1 2 3 4 5 6 7 8; do
        c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/auth/me" -H "Authorization: Bearer $TOKEN")
        [[ "$c" == "200" ]] || bad_replays=$((bad_replays+1))
    done
    (( bad_replays == 0 )) \
        && ok "the token is accepted by every worker (8/8 replays)" \
        || bad "$bad_replays of 8 replays rejected -- workers disagree on the signing key"
else
    bad "admin login failed: $login"
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"organization\":\"${VEYRS_ADMIN_ORG}\",\"email\":\"${VEYRS_ADMIN_EMAIL}\",\"password\":\"definitely-not-the-password\"}")
[[ "$code" == "401" || "$code" == "400" || "$code" == "422" ]] \
    && ok "a wrong password is refused ($code)" \
    || bad "a wrong password answered $code"

# ---------------------------------------------------------------------------
head_ "6. Tenant isolation is REAL (the reason the app role is not a superuser)"

read -r super bypass <<<"$(sql_app "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user" | tr '|' ' ')"
[[ "$super" == "f" ]]  && ok "the application role is NOT a PostgreSQL superuser" \
                       || bad "the application role IS a superuser -- RLS is bypassed entirely"
[[ "$bypass" == "f" ]] && ok "the application role does not have BYPASSRLS" \
                       || bad "the application role has BYPASSRLS"

forced=$(sql_super "SELECT count(*) FROM pg_class WHERE relkind='r' AND relnamespace='public'::regnamespace AND relforcerowsecurity" | tr -d ' ')
[[ "${forced:-0}" -ge 60 ]] \
    && ok "$forced tables carry FORCE ROW LEVEL SECURITY" \
    || bad "only ${forced:-0} tables force RLS (expected >= 60)"

# Pick a STRICT table (its policy has no COALESCE fallback) that actually has
# rows. Chosen dynamically so the test does not encode a table name that a
# later phase renames -- and the "has rows" half is what stops an empty
# database from passing this section trivially.
#
# The row count is a real count(*), NOT pg_class.reltuples. reltuples is a
# planner estimate that is -1 -- not 0 -- for a table that has never been
# ANALYZEd, so the obvious `reltuples <> 0` filter matches every freshly
# created table and happily returns an empty one. That is a MEASUREMENT
# failure, and it reads exactly like a guard that did not bite; it only
# surfaced here because every isolation claim below is paired with a superuser
# read proving the rows are there. Keep the pairing.
strict_tables=$(sql_super "
  SELECT c.relname FROM pg_class c
  JOIN pg_policy p ON p.polrelid = c.oid
  WHERE c.relforcerowsecurity
    AND pg_get_expr(p.polqual, c.oid) NOT LIKE '%COALESCE%'
  ORDER BY c.relname" | tr -d ' \r')
strict_tbl=""
for cand in $strict_tables; do
    n=$(sql_super "SELECT count(*) FROM \"$cand\"" 2>/dev/null | tr -d ' \r')
    [[ "${n:-0}" =~ ^[0-9]+$ ]] && (( n > 0 )) && { strict_tbl="$cand"; break; }
done

if [[ -n "$strict_tbl" ]]; then
    truth=$(sql_super "SELECT count(*) FROM $strict_tbl" | tr -d ' \r')
    unbound=$(sql_app "SELECT count(*) FROM $strict_tbl" | tr -d ' \r')
    if [[ "${truth:-0}" -gt 0 && "${unbound:-x}" == "0" ]]; then
        ok "$strict_tbl: superuser sees $truth rows, the app role with no tenant bound sees 0"
    else
        bad "$strict_tbl: superuser=$truth app-unbound=$unbound -- RLS is not isolating"
    fi
else
    bad "could not find a populated strictly-isolated table to test against"
fi

# Cross-tenant: a second organization, created through the product's own
# command rather than by hand-written INSERTs, so the test exercises the path
# an operator would actually use.
SECOND_ORG="isolation-probe"
"${COMPOSE[@]}" run --rm --no-deps -T api python -m veyrs.cli bootstrap \
    --org "$SECOND_ORG" --email "probe@veyrs.local" \
    --password "probe-tenant-isolation-2026" >/dev/null 2>&1

org_a=$(sql_super "SELECT id FROM organizations WHERE slug='${VEYRS_ADMIN_ORG}'" | tr -d ' \r')
org_b=$(sql_super "SELECT id FROM organizations WHERE slug='${SECOND_ORG}'" | tr -d ' \r')

if [[ -n "$org_a" && -n "$org_b" && "$org_a" != "$org_b" ]]; then
    # `users` is credential-keyed: permissive only while NOTHING is bound, so
    # binding a tenant must still scope it. set_config(..., true) is
    # transaction-local, which is exactly how the application binds it.
    seen_a=$(sql_app "BEGIN; SELECT set_config('veyrs.current_org','$org_a',true); SELECT string_agg(email,',') FROM users; COMMIT;" | grep '@' | tr -d ' \r')
    seen_b=$(sql_app "BEGIN; SELECT set_config('veyrs.current_org','$org_b',true); SELECT string_agg(email,',') FROM users; COMMIT;" | grep '@' | tr -d ' \r')

    if [[ "$seen_a" == *"${VEYRS_ADMIN_EMAIL}"* && "$seen_a" != *"probe@veyrs.local"* ]]; then
        ok "tenant A sees its own user and NOT tenant B's ($seen_a)"
    else
        bad "tenant A saw: '$seen_a' -- expected only ${VEYRS_ADMIN_EMAIL}"
    fi
    if [[ "$seen_b" == *"probe@veyrs.local"* && "$seen_b" != *"${VEYRS_ADMIN_EMAIL}"* ]]; then
        ok "tenant B sees its own user and NOT tenant A's ($seen_b)"
    else
        bad "tenant B saw: '$seen_b' -- expected only probe@veyrs.local"
    fi

    # WITH CHECK, not just USING: a tenant must not be able to WRITE a row
    # belonging to someone else. Reading is the half people test.
    wrote=$(sql_app "BEGIN; SELECT set_config('veyrs.current_org','$org_a',true); INSERT INTO teams (id, organization_id, name, slug) VALUES (gen_random_uuid(), '$org_b', 'smuggled', 'smuggled'); COMMIT;" 2>&1)
    if [[ "$wrote" == *"row-level security"* || "$wrote" == *"violates"* ]]; then
        ok "a cross-tenant INSERT is refused by WITH CHECK"
    elif [[ "$wrote" == *"does not exist"* ]]; then
        note "skipped: no 'teams' table in this schema"
    else
        bad "a cross-tenant INSERT was ACCEPTED: $wrote"
    fi
else
    bad "could not create a second organization to test isolation against"
fi

# ---------------------------------------------------------------------------
head_ "7. The data volume is writable by the account that needs it"

if "${COMPOSE[@]}" exec -T api sh -c 'touch /opt/veyrs/var/.probe && rm /opt/veyrs/var/.probe' 2>/dev/null; then
    ok "uid 10001 can write /opt/veyrs/var"
else
    bad "uid 10001 cannot write /opt/veyrs/var -- reports and evidence will fail at use time, not at startup"
fi

# ---------------------------------------------------------------------------
head_ "8. The console cannot outlive the address it proxies to"

# nginx resolves the names in proxy_pass ONCE, at configuration load, and
# caches the result for the life of the process. Measured 2026-09-22: a
# `docker compose up` that added services recreated `api` on a new address,
# left `console` untouched, and every request through the console returned
#
#   502 ... connect() failed (111: Connection refused) while connecting to
#   upstream, upstream: "http://172.29.0.4:8000/readyz"
#
# with `docker compose ps` reporting BOTH containers healthy -- console's probe
# fetches its own static index, api's probe runs inside api. Green on both
# sides, dead in between.
#
# The fix is a pinned address, so the cache is right by construction. This
# asserts the invariant rather than recreating a container, which would be a
# destructive thing for a test to do to somebody's stack.
conf=$("${COMPOSE[@]}" exec -T console cat /etc/nginx/conf.d/default.conf 2>/dev/null || true)
if [[ -z "$conf" ]]; then
    bad "could not read the console's nginx configuration"
else
    if grep -qE '^[[:space:]]*resolver[[:space:]]+127\.0\.0\.11' <<<"$conf"; then
        ok "the console is configured to re-resolve its upstream"
    else
        bad "the console has no resolver -- nginx will cache the address it saw at startup and serve 502 after any recreate of api"
    fi
    code_only=$(grep -vE '^[[:space:]]*#' <<<"$conf")
    if grep -qE 'proxy_pass[[:space:]]+http://[a-z]' <<<"$code_only"; then
        bad "a proxy_pass uses a literal upstream name: a resolver does not make a literal re-resolve, only a variable does"
    else
        ok "every proxy_pass defers its lookup to request time"
    fi
fi

# `docker compose run` has to keep working: it is `veyrs-docker.sh cli`, and it
# is how the cross-tenant assertions below create their second organization. A
# pinned address for api broke it with "Address already in use".
if "${COMPOSE[@]}" run --rm --no-deps -T api python -c 'print("ok")' >/dev/null 2>&1; then
    ok "docker compose run can still start a second container of the api service"
else
    bad "docker compose run fails -- veyrs-docker.sh cli and the isolation tests below cannot work"
fi

# The round trip that the defect broke: an API response, through nginx.
code=$(curl -s -o /dev/null -w '%{http_code}' "http://${VEYRS_HTTP_BIND:-127.0.0.1:8080}/readyz" || true)
if [[ "$code" == "200" ]]; then
    ok "a request reaches the API through the console (HTTP $code)"
else
    bad "the console answers HTTP $code for /readyz -- check `docker compose logs console` for a stale upstream address"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
exit $(( FAIL > 0 ? 1 : 0 ))
