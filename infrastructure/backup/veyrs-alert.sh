#!/usr/bin/env bash
# Tell a human that a VEYRS backup unit failed.
#
# Called as `veyrs-alert.sh <unit>` by veyrs-alert@.service, which the backup
# units name in OnFailure=. Three channels, all optional and cumulative:
#
#   1. the journal, priority crit, tag veyrs-alert (always; a log shipper or
#      Prometheus journal exporter can alert on it);
#   2. e-mail to VEYRS_ALERT_MAIL when it is set (in /etc/default/veyrs-alert)
#      and `mail`/`mailx` exists on the host;
#   3. an executable /etc/veyrs/alert-hook, called with the unit name and the
#      last journal lines on stdin, for a chat webhook or a pager.
#
# A channel that fails never hides the others, and this script never exits
# non-zero because of a channel: an alert about an alert helps nobody.
set -uo pipefail

UNIT="${1:?usage: veyrs-alert.sh <unit>}"
[ -r /etc/default/veyrs-alert ] && . /etc/default/veyrs-alert

HOST="$(hostname)"
LINES="$(journalctl -u "$UNIT" -n 20 --no-pager 2>/dev/null || true)"
MSG="VEYRS: ${UNIT} FAILED on ${HOST} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

logger -t veyrs-alert -p user.crit "$MSG"

if [ -n "${VEYRS_ALERT_MAIL:-}" ]; then
    MAILER="$(command -v mail || command -v mailx || true)"
    if [ -n "$MAILER" ]; then
        printf '%s\n\nLast journal lines:\n%s\n' "$MSG" "$LINES" | "$MAILER" -s "$MSG" "$VEYRS_ALERT_MAIL" || true
    fi
fi

if [ -x /etc/veyrs/alert-hook ]; then
    printf '%s\n' "$LINES" | /etc/veyrs/alert-hook "$UNIT" || true
fi
exit 0
