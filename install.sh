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
else
    RAW="https://raw.githubusercontent.com/barismd/barisign/main"
fi
# The version on the title is the version being installed, not the old copy:
# fetch just this one small file first (the full download follows). VER stays
# empty when even that fails; the title then has no number.
VER=$(curl -fsSL --connect-timeout 15 --max-time 60 -H 'Cache-Control: no-cache' \
    "$RAW/poc/barisign.py" 2>/dev/null | python3 -c "
import re, sys
m = re.search(r'VERSION *= *[\"\x27]([^\"\x27]+)[\"\x27]', sys.stdin.read())
print(m.group(1) if m else '')
" 2>/dev/null)
: "${VER:=}"

fetch() {   # fetch <file-in-repo> <destination>
    # -f is essential: without it a 404 HTML page is non-empty and would be
    # accepted as a source file (the installer would then compile an error page).
    # The timeouts stop one dead connection from hanging the whole install.
    if curl -fsSL --connect-timeout 15 --max-time 120 -H 'Cache-Control: no-cache' \
            "$RAW/$1" -o "$2" 2>/dev/null && [ -s "$2" ]; then
        return 0
    fi
    if curl -fsSL --connect-timeout 15 --max-time 120 -H 'Cache-Control: no-cache' \
            "https://raw.githubusercontent.com/barismd/barisign/main/$1" -o "$2" 2>/dev/null \
       && [ -s "$2" ]; then
        return 0
    fi
    FAILED="${FAILED:-} $1"
    return 1
}

download_all() {
    fail=0
    _n=0
    for _pair in "poc/poc_login.py poc/poc_login.py" \
                 "poc/poc_portal.py poc/poc_portal.py" \
                 "poc/barisign.py poc/barisign.py" \
                 "poc/signer.py poc/signer.py" \
                 "poc/download.py poc/download.py" \
                 "poc/pair_install.py poc/pair_install.py" \
                 "poc/tls_psk.py poc/tls_psk.py" \
                 "poc/tcp6.py poc/tcp6.py" \
                 "poc/remote_xpc.py poc/remote_xpc.py" \
                 "poc/device_services.py poc/device_services.py" \
                 "poc/devmode.py poc/devmode.py" \
                 "poc/webui.py poc/webui.py" \
                 "poc/pairing.py poc/pairing.py" \
                 "poc/rpp_tunnel.py poc/rpp_tunnel.py" \
                 "poc/mdns.py poc/mdns.py" \
                 "poc/raw_mdns.py poc/raw_mdns.py" \
                 "third_party/sideinstaller/signin.py third_party/sideinstaller/signin.py" \
                 "third_party/sideinstaller/portal.py third_party/sideinstaller/portal.py" \
                 "third_party/apple-roots/apple-roots.pem third_party/apple-roots/apple-roots.pem" \
                 "third_party/ca-bundle/cacert.pem third_party/ca-bundle/cacert.pem" \
                 "variants.json variants.json" \
                 "barisign barisign" \
                 "update update"; do
        # shellcheck disable=SC2086
        set -- $_pair
        if fetch "$1" "$2"; then
            _n=$((_n + 1))
        else
            _n=$((_n + 1))
            fail=1
        fi
        # Same cycling indicator as the other stages: one line,
        # rewritten in place (. → .. → ... → .), no background job.
        case $((_n % 3)) in
            1) _d='.';;
            2) _d='..';;
            *) _d='...';;
        esac
        printf '\r\033[2K  (1/2) files %s' "$_d"
    done
    chmod +x barisign update 2>/dev/null
    return $fail
}

# Prints the files that do not compile, and fails when there is one.
check_compiles() {
    bad=""
    for f in poc/poc_login.py poc/poc_portal.py poc/barisign.py poc/signer.py \
             poc/download.py poc/pair_install.py poc/tls_psk.py poc/tcp6.py \
             poc/remote_xpc.py poc/devmode.py poc/webui.py \
             poc/device_services.py poc/pairing.py poc/rpp_tunnel.py poc/mdns.py \
             poc/raw_mdns.py \
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
        && python3 -c "import sys; sys.path.insert(0, 'poc'); import webui, devmode" \
        && sh -n barisign && sh -n update
}

# No background jobs: a-Shell's shell can leave a background spinner
# looping in the terminal.  Progress is one line per phase, rewritten in
# place (. → .. → ... → .).  Each finished phase clears the screen, so a
# finished installer always ends on one clean screen.
clear_screen() {
    # Same order as the guided flow: scroll the page away first, then drop
    # the scrollback, or a-Shell shows a blank page the user must scroll
    # back to. No tput/cut/rev on a-Shell; parse stty with the shell itself.
    rows=$(stty size 2>/dev/null)
    rows=${rows%% *}
    case "$rows" in
        ''|*[!0-9]*) rows=24;;
    esac
    printf '\033[0m'
    i=0
    while [ "$i" -lt "$((rows * 2))" ]; do printf '\n'; i=$((i + 1)); done
    printf '\033[3J'
    i=0
    while [ "$i" -lt "$rows" ]; do printf '\n'; i=$((i + 1)); done
    printf '\033[2J\033[1;1H'
}

clear_screen
printf 'installing BariSign%s\n\n' "${VER:+" $VER"}"

attempt=1
while [ "$attempt" -le 2 ]; do
    FAILED=""
    download_all
    if [ "$fail" -eq 0 ]; then
        clear_screen
        printf 'installing BariSign%s\n\n' "${VER:+" $VER"}"
    else
        printf '\r\033[2K  (1/2) files failed\n'
        printf '  ! could not fetch:%s\n' "$FAILED"
    fi

    printf '  (2/2) check ...'
    COMPILE_BAD=""
    if [ "$fail" -eq 0 ] && COMPILE_BAD=$(check_compiles) && works; then
        clear_screen
        break
    fi
    printf '\r\033[2K  (2/2) check failed\n'
    if [ -n "${COMPILE_BAD:-}" ]; then
        printf '  ! does not compile:%s\n' "$COMPILE_BAD"
    fi
    if [ "$attempt" -lt 2 ]; then
        printf '  ! retrying in 5 s\n'
        sleep 5
    fi
    attempt=$((attempt + 1))
done

if [ "$fail" -ne 0 ] || ! works; then
    printf '  ! install failed; nothing was changed outside the program files.\n'
    printf '    check the network (Safari should open github.com) and run sh install.sh again.\n'
    exit 1
fi
if [ -d bin ]; then
    rm -rf bin
    printf '  retired    bin/ (now: sh barisign, sh update, sh barisignone)\n'
fi
printf 'BariSign %s installed\n\n' "${VER:-?}"
printf '  sh barisign ready (opens the page)\n'
printf '  sh barisignone for the one-device experiment\n'
printf '  help: sh barisign help\n'
