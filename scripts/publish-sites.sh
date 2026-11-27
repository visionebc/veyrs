#!/usr/bin/env bash
# Publish the console, the Docs Center and the product site on THIS node (TD-43, TD-44).
#
# Run it on every application node after the checkout is updated. Each tree is
# built beside its live directory and swapped in atomically (site/atomic_swap.py),
# so a page load never meets a half-written site or a missing /static/. The
# previous tree stays in <root>.prev for a one-command rollback:
#     mv /var/www/veyrs /var/www/veyrs.bad && mv /var/www/veyrs.prev /var/www/veyrs
#
# At the end it prints one fingerprint per tree. Run the script on both nodes
# and compare the lines: equal fingerprints mean equal sites (the Docs Center
# build is deterministic for one checkout).
#
# Usage:
#   scripts/publish-sites.sh [--docs-root DIR] [--web-root DIR] [--console-root DIR]
#                            [--only docs,web,console] [--dry-run]
# Defaults: /var/www/veyrs, /var/www/veyrs-web, /var/www/veyrs-console.
# VEYRS_SITE_CONSOLE_URL / VEYRS_SITE_DOCS_URL are passed to the product-site build.
#
# Needs root only to write the document roots and to keep www-data ownership.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS_ROOT=/var/www/veyrs
WEB_ROOT=/var/www/veyrs-web
CONSOLE_ROOT=/var/www/veyrs-console
ONLY="docs,web,console"
DRY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docs-root)    DOCS_ROOT="$2"; shift 2 ;;
        --web-root)     WEB_ROOT="$2"; shift 2 ;;
        --console-root) CONSOLE_ROOT="$2"; shift 2 ;;
        --only)         ONLY="$2"; shift 2 ;;
        --dry-run)      DRY=1; shift ;;
        -h|--help)      sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

want() { [[ ",$ONLY," == *",$1,"* ]]; }
say()  { printf '==> %s\n' "$*"; }

# A stable fingerprint of a tree: every file's md5 and relative path, sorted,
# hashed again. Independent of mtimes and of the directory it sits in.
fingerprint() {
    (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum | md5sum | cut -d' ' -f1)
}

stage_dir() {   # a fresh directory beside the live one (same filesystem => atomic rename)
    local live="$1"
    mkdir -p "$(dirname "$live")"
    mktemp -d "$(dirname "$live")/$(basename "$live").new-XXXXXX"
}

publish() {     # publish <name> <live> <staged>
    local name="$1" live="$2" staged="$3"
    if [[ $DRY -eq 1 ]]; then
        say "[dry-run] would swap $staged into $live"
        rm -rf "$staged"
        return
    fi
    python3 "$SRC/site/atomic_swap.py" "$staged" "$live"
    REPORT+=("$name  $(fingerprint "$live")  $(find "$live" -type f | wc -l) files  $live")
}

REPORT=()
STAGED=()
trap 'for d in "${STAGED[@]:-}"; do [[ -n "$d" ]] && rm -rf "$d"; done' EXIT

if want docs; then
    say "Docs Center -> $DOCS_ROOT"
    if [[ $DRY -eq 1 ]]; then
        T="$(mktemp -d)"; STAGED+=("$T")
        python3 "$SRC/site/build.py" --out "$T/docs" | tail -1
    else
        python3 "$SRC/site/build.py" --out "$DOCS_ROOT" | tail -1   # builds beside and swaps itself
        REPORT+=("docs     $(fingerprint "$DOCS_ROOT")  $(find "$DOCS_ROOT" -type f | wc -l) files  $DOCS_ROOT")
    fi
fi

if want web; then
    say "product site -> $WEB_ROOT"
    S="$(stage_dir "$WEB_ROOT")"; STAGED+=("$S")
    python3 "$SRC/site/web/build_web.py" --out "$S" | tail -3
    publish web "$WEB_ROOT" "$S"
fi

if want console; then
    say "console -> $CONSOLE_ROOT (app, fonts, brand under /static/)"
    S="$(stage_dir "$CONSOLE_ROOT")"; STAGED+=("$S")
    cp -a "$SRC/frontend/console/." "$S/"           # the whole directory, fonts included
    mkdir -p "$S/static"
    cp "$SRC/frontend/brand/veyrs-tokens.css" "$S/static/"
    cp "$SRC"/frontend/brand/logo/*.png "$SRC"/frontend/brand/logo/*.ico "$SRC"/frontend/brand/logo/*.svg "$S/static/"
    for f in index.html app.js console.css; do
        [[ -f "$S/$f" ]] || { echo "console build is missing $f" >&2; exit 1; }
    done
    publish console "$CONSOLE_ROOT" "$S"
fi

echo
echo "fingerprints (compare between nodes):"
printf '  %s\n' "${REPORT[@]:-(nothing published: --dry-run)}"
