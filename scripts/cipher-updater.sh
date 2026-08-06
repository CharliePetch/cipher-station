#!/bin/bash
# Cipher Station auto-updater.
#
# Runs from a systemd timer (cipherstation-updater.timer, installed by
# install.sh). Two modes, chosen by what /etc/cipher-updater.env carries:
#
#   Hosted (managed fleet):  CIPHER_UPDATE_URL + CIPHER_UPDATE_TOKEN +
#     CIPHER_UPDATE_SERVER_ID. Each run POSTs a check-in (reporting the
#     running commit) to the control plane's phonehome endpoint and gets the
#     operator-pinned desired SHA back. The pin is a deliberate promote step
#     on the control plane — this box never follows a branch.
#
#   Self-host (opt-in):  CIPHER_AUTO_UPDATE_REF=<branch>. Fetches origin and
#     converges on that branch's tip. Written only when the owner passed
#     CIPHER_AUTO_UPDATE=true to install.sh — updating hardware we don't
#     manage is opt-in, never default.
#
# Update = git checkout of the desired commit + re-run of install.sh (the
# sanctioned upgrade path: it rewrites units and restarts services; station
# data lives under CIPHER_BASE_DIR/CIPHER_DATA_ROOT and is never touched by
# the clone). After the restart the station must answer /health; if it does
# not, the previous commit is checked out and installed again, and the
# failure is reported so the operator hears about it instead of a customer.
#
# This file is COPIED to /usr/local/bin/cipher-updater by install.sh and runs
# from there, so the running script is never modified by the checkout it
# performs.

set -u

UPDATER_ENV="/etc/cipher-updater.env"
LOCK_FILE="/run/cipher-updater.lock"

log() { echo "$*"; }  # stdout lands in the journal

[ -f "$UPDATER_ENV" ] || { log "no $UPDATER_ENV — updater not configured"; exit 0; }
# shellcheck disable=SC1090
. "$UPDATER_ENV"

CLONE_DIR="${CIPHER_CLONE_DIR:-/opt/cipher-station}"
PORT="${CIPHER_PORT:-8443}"

[ -d "$CLONE_DIR/.git" ] || { log "no git clone at $CLONE_DIR"; exit 0; }

# One run at a time; a second timer firing while an update (or a slow install)
# is in flight must not start a competing checkout.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "another updater run is in progress — skipping"
    exit 0
fi

current="$(git -C "$CLONE_DIR" rev-parse HEAD 2>/dev/null || true)"
[ -n "$current" ] || { log "cannot read current commit"; exit 0; }

checkin() {
    # checkin <json-body> — POST to the control plane; echoes the response
    # body. Best-effort: a dead control plane must never break a running
    # station, so callers treat empty output as "no instruction".
    curl -sS -m 15 -X POST "${CIPHER_UPDATE_URL}/api/phonehome/${CIPHER_UPDATE_SERVER_ID}" \
        -H "Authorization: Bearer ${CIPHER_UPDATE_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$1" 2>/dev/null || true
}

desired=""
if [ -n "${CIPHER_UPDATE_URL:-}" ] && [ -n "${CIPHER_UPDATE_TOKEN:-}" ] && [ -n "${CIPHER_UPDATE_SERVER_ID:-}" ]; then
    resp="$(checkin "{\"outcome\":\"checkin\",\"runningSha\":\"${current}\"}")"
    # Extract without a jq dependency; the value is a bare 40-hex SHA.
    desired="$(printf '%s' "$resp" | grep -oE '"desiredSha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' | grep -oE '[0-9a-f]{40}' | head -1 || true)"
    [ -n "$desired" ] || { log "check-in ok, no usable desiredSha — nothing to do"; exit 0; }
elif [ -n "${CIPHER_AUTO_UPDATE_REF:-}" ]; then
    git -C "$CLONE_DIR" fetch --quiet origin || { log "git fetch failed"; exit 0; }
    desired="$(git -C "$CLONE_DIR" rev-parse "origin/${CIPHER_AUTO_UPDATE_REF}" 2>/dev/null || true)"
    [ -n "$desired" ] || { log "cannot resolve origin/${CIPHER_AUTO_UPDATE_REF}"; exit 0; }
else
    log "updater env carries neither hosted nor self-host settings — nothing to do"
    exit 0
fi

[ "$desired" = "$current" ] && exit 0
case "$desired" in
    *[!0-9a-f]*) log "desired SHA is not lowercase hex: $desired"; exit 0 ;;
esac
if [ "${#desired}" -ne 40 ]; then
    log "desired SHA is not 40 chars: $desired"
    exit 0
fi

log "update available: $current -> $desired"

cd "$CLONE_DIR" || exit 0
git fetch --quiet origin || { log "git fetch failed"; exit 0; }
if ! git cat-file -e "${desired}^{commit}" 2>/dev/null; then
    log "desired commit $desired not found in origin — refusing"
    checkin "{\"outcome\":\"update_failed\",\"exitCode\":10}" >/dev/null
    exit 0
fi

health_ok() {
    # /health answers 200 only when database + IPFS + identity all check out
    # (503 otherwise), so the status code is the whole test. The station
    # serves TLS on localhost (self-signed behind the tunnel), hence -k; the
    # plain-HTTP probe covers configs that run without TLS.
    for _i in $(seq 1 30); do
        code="$(curl -skm 5 -o /dev/null -w '%{http_code}' "https://localhost:${PORT}/health" 2>/dev/null || true)"
        [ "$code" = "200" ] && return 0
        code="$(curl -sm 5 -o /dev/null -w '%{http_code}' "http://localhost:${PORT}/health" 2>/dev/null || true)"
        [ "$code" = "200" ] && return 0
        sleep 5
    done
    return 1
}

run_install() {
    # Re-run install.sh the way the provisioner would: the hosted knobs come
    # from the updater env so restart semantics and volume paths are preserved.
    CIPHER_DATA_ROOT="${CIPHER_DATA_ROOT:-}" \
    CIPHER_STORAGE_MAX="${CIPHER_STORAGE_MAX:-}" \
    bash "$CLONE_DIR/install.sh" >>/var/log/cipher-update.log 2>&1
}

git checkout --quiet --detach "$desired" || { log "checkout failed"; exit 0; }

if run_install && health_ok; then
    log "updated to $desired and healthy"
    checkin "{\"outcome\":\"checkin\",\"runningSha\":\"${desired}\"}" >/dev/null
    exit 0
fi

log "update to $desired FAILED health check — rolling back to $current"
git checkout --quiet --detach "$current" || {
    log "ROLLBACK CHECKOUT FAILED — manual intervention required"
    checkin "{\"outcome\":\"update_failed\",\"exitCode\":12}" >/dev/null
    exit 1
}
if run_install && health_ok; then
    log "rollback to $current succeeded"
    checkin "{\"outcome\":\"update_failed\",\"exitCode\":11}" >/dev/null
else
    log "ROLLBACK DID NOT COME BACK HEALTHY — manual intervention required"
    checkin "{\"outcome\":\"update_failed\",\"exitCode\":13}" >/dev/null
fi
exit 0
