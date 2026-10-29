#!/usr/bin/env bash
# Scanner-agent entrypoint.
#
# The agent itself already refuses to start without VEYRS_URL,
# VEYRS_AGENT_TOKEN or a non-empty VEYRS_AGENT_ALLOW (veyrs_agent.py, main()),
# and those guards are NOT repeated here: a rule written twice is a rule that
# drifts, and the copy nobody runs by hand is the one that rots.
#
# This file exists for the one failure mode that is unique to a container.
set -uo pipefail

TEMPLATES="${NUCLEI_TEMPLATES:-/opt/veyrs/agent-home/nuclei-templates}"
export HOME="${HOME:-/opt/veyrs/agent-home}"

# ===========================================================================
# A nuclei with no templates SCANS CLEAN. It does not error.
# ===========================================================================
# This is the same failure the host unit is built around -- veyrs-agent.service
# deliberately omits ProtectHome, with a comment saying why, because locking
# /root turns every scan into a silent zero-template run. In a container the
# trap is different but the outcome is identical: the templates live in a named
# volume, a volume starts EMPTY, and an agent that starts against an empty
# corpus reports "0 findings" for every asset it is pointed at. Nothing errors,
# the job completes, the dashboard goes green, and the platform's entire reason
# for existing has quietly stopped working.
#
# So: seed if empty, and REFUSE TO START if the seeding did not produce a
# corpus. A scanner that cannot scan must fail loudly at boot, not silently at
# every job.
# ===========================================================================
mkdir -p "$TEMPLATES"

count_templates() { find "$TEMPLATES" -name '*.yaml' -type f 2>/dev/null | head -200 | wc -l; }

if [ "$(count_templates)" -lt 100 ]; then
    echo "veyrs-agent: template directory is empty, downloading the corpus"
    # ~84 MB. Not baked into the image on purpose: templates change daily, so a
    # container that has been up for a month would scan with a month-old corpus
    # and say nothing about it. In a volume, `update-templates` refreshes them
    # in place.
    nuclei -update-templates -update-template-dir "$TEMPLATES" -silent \
        || echo "veyrs-agent: template download reported an error" >&2
fi

if [ "$(count_templates)" -lt 100 ]; then
    cat >&2 <<EOF
veyrs-agent: refusing to start.

  No nuclei templates under ${TEMPLATES}.

  An agent started this way does not fail: it runs every job it is handed,
  finds nothing, and reports a clean scan for assets that were never actually
  tested. That is worse than being down, because a down agent is visible.

  Either give the container outbound access to github.com so the corpus can be
  fetched, or mount an existing template directory at ${TEMPLATES}.
EOF
    exit 78   # EX_CONFIG
fi

echo "veyrs-agent: $(find "$TEMPLATES" -name '*.yaml' -type f | wc -l) templates under ${TEMPLATES}"
export NUCLEI_TEMPLATES="$TEMPLATES"

# Any argument means "run this instead" -- a shell, or nuclei by hand.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# --poll/--job-timeout mirror the host unit's ExecStart.
exec python /opt/veyrs/integrations/veyrs-agent/veyrs_agent.py \
    --poll "${VEYRS_AGENT_POLL:-5}" \
    --job-timeout "${VEYRS_AGENT_JOB_TIMEOUT:-1800}"
