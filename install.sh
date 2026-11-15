#!/bin/sh
# =============================================================================
#  BariSign installer — downloads every file it needs. No git required.
#
#  In a-Shell:
#      mkdir -p ~/Documents/barisign && cd ~/Documents/barisign
#      curl -sSL "https://github.com/barismd/barisign/blob/main/install.sh?raw=true" -o install.sh
#      sh install.sh
#
#  Run it again any time to update: it overwrites the program files and leaves the
#  saved state in state/ alone, so your Apple ID, UDID and profile stay.
# =============================================================================

set -u

BASE="https://github.com/barismd/barisign/blob/main"
DIR="${BARISIGN_DIR:-$HOME/Documents/barisign}"

printf 'BariSign installer\n\n'

mkdir -p "$DIR/poc" "$DIR/bin" "$DIR/third_party/sideinstaller" \
         "$DIR/third_party/apple-roots" "$DIR/third_party/ca-bundle" || {
    printf '  ! cannot create %s (a-Shell only writes inside ~/Documents)\n' "$DIR"
    exit 1
}
cd "$DIR" || exit 1

# GitHub caches the /main/ URLs for a while after a push, and the unauthenticated
# API rate-limits, so neither can be trusted for a fresh install. Instead we read
# the newest commit id from the public atom feed (not rate-limited) and download
# every file *pinned to that commit*: those URLs are immutable, so the set can
# never be a mix of two revisions.
ATOM="https://github.com/barismd/barisign/commits/main.atom"
# a-Shell has no rev/cut/head, so the commit id is read with python3 alone.
SHA=$(curl -sSL --max-time 25 "$ATOM" 2>/dev/null | python3 -c "
import re, sys
found = re.search(r'barismd/barisign/commit/([0-9a-f]{40})', sys.stdin.read())
print(found.group(1) if found else '')
" 2>/dev/null)
if [ -n "${SHA:-}" ]; then
    RAW="https://raw.githubusercontent.com/barismd/barisign/$SHA"
    printf '  revision  %.7s\n' "$SHA"
else
    RAW="https://raw.githubusercontent.com/barismd/barisign/main"
    printf '  revision  main (not pinned)\n'
    printf '  ! the commit id could not be read; GitHub can serve an older copy\n'
fi

fetch() {   # fetch <file-in-repo> <destination>
    # -f is essential: without it a 404 HTML page is non-empty and would be
    # accepted as a source file (the installer would then compile an error page).
    if curl -fsSL -H 'Cache-Control: no-cache' "$RAW/$1" -o "$2" 2>/dev/null && [ -s "$2" ]; then
        return 0
    fi
    if curl -fsSL -H 'Cache-Control: no-cache' \
            "https://raw.githubusercontent.com/barismd/barisign/main/$1" -o "$2" 2>/dev/null \
       && [ -s "$2" ]; then
        return 0
    fi
    FAILED="${FAILED:-} $1"
    return 1
}

download_all() {
    fail=0
    fetch poc/poc_login.py                    poc/poc_login.py                 || fail=1
    fetch poc/poc_portal.py                   poc/poc_portal.py                || fail=1
    fetch poc/barisign.py                     poc/barisign.py                  || fail=1
    fetch poc/signer.py                       poc/signer.py                    || fail=1
    fetch poc/download.py                     poc/download.py                  || fail=1
    fetch poc/pair_probe.py                   poc/pair_probe.py                || fail=1
    fetch poc/pair_install.py                 poc/pair_install.py              || fail=1
    fetch poc/ashell_bonjour.py               poc/ashell_bonjour.py            || fail=1
    fetch poc/tls_psk.py                      poc/tls_psk.py                   || fail=1
    fetch poc/tcp6.py                         poc/tcp6.py                      || fail=1
    fetch poc/remote_xpc.py                   poc/remote_xpc.py                || fail=1
    fetch poc/device_services.py              poc/device_services.py           || fail=1
    fetch poc/pairing.py                      poc/pairing.py                   || fail=1
    fetch poc/rpp_tunnel.py                   poc/rpp_tunnel.py                || fail=1
    fetch poc/mdns.py                         poc/mdns.py                      || fail=1
    fetch poc/bonjour_check.py                poc/bonjour_check.py             || fail=1
    fetch poc/raw_mdns.py                     poc/raw_mdns.py                  || fail=1
    fetch third_party/sideinstaller/signin.py third_party/sideinstaller/signin.py || fail=1
    fetch third_party/sideinstaller/portal.py third_party/sideinstaller/portal.py || fail=1
    fetch third_party/apple-roots/apple-roots.pem third_party/apple-roots/apple-roots.pem || fail=1
    fetch third_party/ca-bundle/cacert.pem    third_party/ca-bundle/cacert.pem || fail=1
    fetch variants.json                       variants.json                    || fail=1
    fetch bin/barisign                        bin/barisign                     || fail=1
    fetch bin/update                          bin/update                       || fail=1
    chmod +x bin/* 2>/dev/null
    return $fail
}

# Prints the files that do not compile, and fails when there is one.
check_compiles() {
    bad=""
    for f in poc/poc_login.py poc/poc_portal.py poc/barisign.py poc/signer.py \
             poc/download.py poc/pair_probe.py poc/pair_install.py \
             poc/ashell_bonjour.py poc/tls_psk.py poc/tcp6.py poc/remote_xpc.py \
             poc/device_services.py poc/pairing.py poc/rpp_tunnel.py poc/mdns.py \
             poc/bonjour_check.py poc/raw_mdns.py \
             third_party/sideinstaller/signin.py \
             third_party/sideinstaller/portal.py; do
        if ! python3 -c "compile(open('$f').read(), 'x', 'exec')" 2>/dev/null; then
            bad="$bad $f"
        fi
    done
    [ -z "$bad" ] && return 0
    printf '%s\n' "$bad"
    return 1
}

# Compiling is not enough: a half-stale set compiles and then fails on import.
# The wrappers are shell, so check their syntax too.
works() {
    python3 poc/barisign.py --help >/dev/null 2>&1 \
        && python3 poc/poc_portal.py --help >/dev/null 2>&1 \
        && python3 poc/pair_install.py --check >/dev/null 2>&1 \
        && sh -n bin/barisign && sh -n bin/update
}

# Run one phase in the background while a foreground loop animates the
# indicator.  A "done" file (not kill -0) ends the loop, so the spinner can
# never become an orphan and the phase always ends with ok/failed.  The
# phase writes its result to the same directory.
progress_run() {   # <label> <phase-function>
    _label="$1"
    _fn="$2"
    _dir="$PWD/.progress.$$"
    rm -rf "$_dir"
    mkdir -p "$_dir" || {
        PROGRESS_STATUS=1
        PROGRESS_FAILED=""
        PROGRESS_BAD=""
        return 1
    }
    PROGRESS_DIR="$_dir"
    export PROGRESS_DIR
    "$_fn" &
    _pid=$!
    _active_pid="$_pid"
    _i=0
    _dots=''
    while [ ! -f "$_dir/done" ] && [ "$_i" -lt 3600 ]; do
        case "$_dots" in
            '') _dots='.';;
            '.') _dots='..';;
            '..') _dots='...';;
            *) _dots='';;
        esac
        printf '\r\033[2K  %-9s %s' "$_label" "$_dots"
        sleep 1
        _i=$((_i + 1))
    done
    wait "$_pid" 2>/dev/null
    _active_pid=""
    PROGRESS_STATUS=$(cat "$_dir/status" 2>/dev/null || echo 1)
    PROGRESS_FAILED=$(cat "$_dir/failed" 2>/dev/null || echo "")
    PROGRESS_BAD=$(cat "$_dir/bad" 2>/dev/null || echo "")
    rm -rf "$_dir"
    return 0
}

fetch_phase() {
    trap ': > "$PROGRESS_DIR/done"' 0
    download_all
    printf '%s' "$fail" > "$PROGRESS_DIR/status"
    printf '%s' "${FAILED:-}" > "$PROGRESS_DIR/failed"
    : > "$PROGRESS_DIR/done"
}

check_phase() {
    trap ': > "$PROGRESS_DIR/done"' 0
    _bad=$(check_compiles)
    _rc=0
    if [ -n "$_bad" ] || ! works; then
        _rc=1
    fi
    printf '%s' "$_rc" > "$PROGRESS_DIR/status"
    printf '%s' "$_bad" > "$PROGRESS_DIR/bad"
    : > "$PROGRESS_DIR/done"
}

trap 'if [ -n "${_active_pid:-}" ]; then kill "$_active_pid" 2>/dev/null; fi; rm -rf "$PWD/.progress.$$"; exit 130' 1 2 15

attempt=1
while [ "$attempt" -le 2 ]; do
    FAILED=""
    progress_run "files" fetch_phase
    fail="$PROGRESS_STATUS"
    FAILED="$PROGRESS_FAILED"
    if [ "$fail" -eq 0 ]; then
        printf '\r\033[2K  files     ok\n'
    else
        printf '\r\033[2K  files     failed\n'
        printf '  ! could not fetch:%s\n' "$FAILED"
    fi

    progress_run "check" check_phase
    COMPILE_BAD="$PROGRESS_BAD"
    if [ "$fail" -eq 0 ] && [ "$PROGRESS_STATUS" -eq 0 ]; then
        printf '\r\033[2K  check     ok\n'
        break
    fi
    printf '\r\033[2K  check     failed\n'
    if [ -n "${COMPILE_BAD:-}" ]; then
        printf '  ! does not compile:%s\n' "$COMPILE_BAD"
    fi
    if [ "$attempt" -lt 2 ]; then
        printf '  ! retrying in 5 s\n'
        sleep 5
    fi
    attempt=$((attempt + 1))
done

printf '\n'
if [ "$fail" -ne 0 ] || ! works; then
    printf '  ! install failed; nothing was changed outside the program files.\n'
    printf '    check the network (Safari should open github.com) and run sh install.sh again.\n'
    exit 1
fi
printf '  ready     sh bin/barisign\n'
