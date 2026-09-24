# VEYRS container images. Build context is the REPOSITORY ROOT, not this
# directory:
#
#   docker build -f docker/Dockerfile --target api     -t veyrs:local .
#   docker build -f docker/Dockerfile --target console -t veyrs-console:local .
#
# Normally invoked through docker/veyrs-docker.sh, which gets the context and
# the two targets right without anyone having to remember them.
#
# Python 3.11 matches the production node (3.11.2) and the interpreter
# requirements.txt was frozen against. Every pinned dependency resolves to a
# manylinux wheel on x86-64, so there is no compiler in this image on purpose:
# a build toolchain left in a runtime image is attack surface that never runs.

# ---------------------------------------------------------------------------
# api — FastAPI/uvicorn, and the same image the one-shot `init` service runs.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS api

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/veyrs/backend

WORKDIR /opt/veyrs

# Dependencies first, in their own layer: requirements.txt changes far less
# often than the source, so editing a handler does not re-resolve 64 packages.
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# EXPLICIT copies, never `COPY . .`.
#
# This is not tidiness. The repository working tree carries `.env`,
# `.bootstrap-credentials` and `var/backups/` -- the live VEYRS_SECRET_KEY, the
# live Fernet key and a production dump. `COPY . .` bakes all three into an
# image layer, where they survive every later `rm` because layers are additive,
# and they travel to anyone the image is shared with. There is a
# `.dockerignore` at the repository root as a second line of defence, and a
# test that fails if either control is removed.
COPY backend/ ./backend/
COPY scripts/ ./scripts/
COPY docker/entrypoint.sh docker/init.sh docker/tick.sh ./docker/
RUN chmod +x ./docker/entrypoint.sh ./docker/init.sh ./docker/tick.sh

# A dedicated account, NOT root.
#
# This deliberately DIFFERS from the host install, where veyrs-api.service runs
# as root and compensates with ProtectSystem=strict + ReadWritePaths. That is a
# documented limitation of the host unit, not a recommendation, and a container
# has no reason to inherit it: there is nothing outside /opt/veyrs/var this
# process ever writes.
#
# The uid is pinned. A named user whose uid drifts between rebuilds leaves the
# files in the `veyrs-var` volume owned by a number this image no longer maps,
# and the app fails to write evidence and reports -- after starting cleanly.
RUN groupadd --gid 10001 veyrs \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin veyrs \
 && mkdir -p /opt/veyrs/var \
 && chown -R 10001:10001 /opt/veyrs/var

USER 10001:10001

EXPOSE 8000

# Probes /readyz, which checks BOTH Postgres and Redis and answers 503 when
# either is down. /healthz would be wrong here: it returns 200 from a process
# that has lost its database, so the container would report healthy while
# every request 500s.
#
# No curl in this image (see above); urllib is already installed. A 503 raises
# HTTPError, which exits non-zero -- exactly what is wanted.
HEALTHCHECK --interval=10s --timeout=5s --start-period=45s --retries=6 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4)"]

ENTRYPOINT ["/opt/veyrs/docker/entrypoint.sh"]

# ---------------------------------------------------------------------------
# console — the operator UI, plus the same-origin /api proxy.
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS console

# The console is three files; `/static/` is the brand directory flattened.
#
# On a host install those two live under DIFFERENT document roots and nginx
# bridges them with `alias /var/www/veyrs/static/` from the console vhost --
# which is why a console served without the documentation site present renders
# unstyled: veyrs-tokens.css defines every colour token and resolves to 404.
# Baking both into one image removes that cross-vhost dependency entirely.
COPY frontend/console/ /usr/share/nginx/html/
COPY frontend/brand/logo/ /usr/share/nginx/html/static/
COPY frontend/brand/veyrs-tokens.css /usr/share/nginx/html/static/veyrs-tokens.css
COPY docker/console.conf /etc/nginx/conf.d/default.conf

# Overwriting conf.d/default.conf rather than adding a second file: the stock
# one claims default_server on :80, so a new server block that merely sits
# beside it loses on parse order and the operator gets the nginx welcome page
# from a stack that reports healthy. Measured on SATOM, 2026-08-31.

HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
  CMD wget -qO /dev/null http://127.0.0.1/ || exit 1

# ---------------------------------------------------------------------------
# agent — the scanner runner. OPT-IN (compose profile `agent`), never default.
#
# Built FROM api because it shares the interpreter and the dependency set, and
# because one pip resolution for two images is one pip resolution.
#
#   docker build -f docker/Dockerfile --target agent -t veyrs-agent:local .
#
# Read docker/README.md before running this. An agent is the one part of VEYRS
# that sends unsolicited traffic to other people's machines; an evaluation
# stack that arrived with one running would be scanning before its operator had
# decided what it is allowed to touch.
# ---------------------------------------------------------------------------
FROM api AS agent

# Back to root for the install, and back to 10001 before the entrypoint. The
# api stage ends as uid 10001, which cannot apt-get.
USER 0:0

ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH=amd64

# Pinned AND checksummed. A scanner binary fetched over the network at build
# time with no verification is a supply-chain hole in the one component whose
# whole job is to be pointed at things and trusted about what it finds.
ARG NUCLEI_SHA256_amd64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_arm64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    case "${TARGETARCH}" in \
      amd64) sha="${NUCLEI_SHA256_amd64}" ;; \
      arm64) sha="${NUCLEI_SHA256_arm64}" ;; \
      *) echo "no pinned nuclei checksum for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    zip="nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSL -o "/tmp/${zip}" \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${zip}"; \
    echo "${sha}  /tmp/${zip}" | sha256sum -c -; \
    unzip -q "/tmp/${zip}" -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf "/tmp/${zip}" /tmp/nuclei; \
    apt-get purge -y --auto-remove unzip; \
    rm -rf /var/lib/apt/lists/*; \
    nuclei -version

# The agent's own source is NOT in the api stage: the API never runs it.
COPY integrations/veyrs-agent/ ./integrations/veyrs-agent/
COPY docker/agent-entrypoint.sh ./docker/
RUN chmod +x ./docker/agent-entrypoint.sh

# A writable HOME, because nuclei keeps its config, cache and template corpus
# there. The host unit solves the same problem by NOT setting ProtectHome and
# letting it use /root; here the directory is owned by the unprivileged uid and
# is normally a volume, so the ~84 MB corpus survives a recreate and can be
# refreshed in place instead of being frozen into an image layer.
ENV HOME=/opt/veyrs/agent-home \
    NUCLEI_TEMPLATES=/opt/veyrs/agent-home/nuclei-templates
RUN mkdir -p "$HOME" && chown -R 10001:10001 "$HOME"

USER 10001:10001

# No HEALTHCHECK. The agent opens no port and polls outbound; the only honest
# liveness signal is the lease it holds on the server, which
# `POST /api/v1/agents/maintenance/reap` already collects. A probe that always
# passes would be decoration on the column meant to carry the alarm.
HEALTHCHECK NONE

ENTRYPOINT ["/opt/veyrs/docker/agent-entrypoint.sh"]
