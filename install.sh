#!/bin/sh
# =============================================================================
#  BariSign installer — downloads every file it needs. No git required.
#
#  In a-Shell, one line is enough (run it from anywhere):
#      curl -fsSL https://raw.githubusercontent.com/barismd/barisign/main/install.sh | sh
#
#  What it lays down in ~/Documents:
#      barisign          the launcher: `sh barisign` from Documents, no cd needed
#      barisign_files/   everything else (poc/, state/, ipa/, third_party/...)
#
#  Run it again any time to update: it overwrites the program files and leaves
#  the saved state in barisign_files/state/ alone, so your Apple ID, UDID and
#  profile stay. Old layouts (barisign/ as program dir, bin/, barisignone)
#  are migrated/retired in place.
# =============================================================================

set -u

# Re-run through a temp copy when invoked as the installed file itself: the
# run overwrites install.sh with the newest copy, which would corrupt a
# script reading itself.
case "$0" in
*/barisign_files/install.sh|install.sh)
    _self=".install.sh.run-$$"
    cp -f "$0" "$_self" || exit 1
    exec sh "$_self" "$@"
    ;;
esac
for _old in .install.sh.run-*; do
    case "$_old" in
        *"$$") ;;
        *) rm -f "$_old" ;;
    esac
done

BASE="https://github.com/barismd/barisign/blob/main"
DOCS="$HOME/Documents"
PROG="${BARISIGN_DIR:-$DOCS/barisign_files}"

# Migrate the pre-0.9.25 layout: the program lived directly in barisign/.
# Whatever that directory is (full install or a stray dir), it must not block
# the launcher file of the same name: adopt it as the program dir, or park it.
if [ -d "$DOCS/barisign" ]; then
    if [ ! -e "$PROG" ]; then
        mv "$DOCS/barisign" "$PROG" 2>/dev/null && \
            printf '  moved      barisign/ -> barisign_files/\n'
    else
        mv "$DOCS/barisign" "$DOCS/barisign_legacy" 2>/dev/null && \
            printf '  parked     stray barisign/ -> barisign_legacy/\n'
    fi
fi

mkdir -p "$PROG/poc" "$PROG/third_party/sideinstaller" \
         "$PROG/third_party/apple-roots" "$PROG/third_party/ca-bundle" || {
    printf '  ! cannot create %s (a-Shell only writes inside ~/Documents)\n' "$PROG"
    exit 1
}
cd "$PROG" || exit 1
# Leftovers of older layouts, inside the program dir now.
rm -rf "$PROG/bin" "$PROG/barisignone" "$PROG/update" "$PROG/barisign" 2>/dev/null

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
    _updated=0
    _current=0
    for _file in poc/poc_login.py poc/poc_portal.py poc/barisign.py poc/signer.py \
                 poc/download.py poc/pair_install.py poc/tls_psk.py poc/tcp6.py \
                 poc/remote_xpc.py poc/devmode.py poc/webui.py \
                 poc/device_services.py poc/pairing.py poc/rpp_tunnel.py poc/mdns.py \
                 poc/raw_mdns.py \
                 third_party/sideinstaller/signin.py third_party/sideinstaller/portal.py \
                 third_party/apple-roots/apple-roots.pem third_party/ca-bundle/cacert.pem \
                 variants.json install.sh; do
        if fetch "$_file" "$_file.part"; then
            _n=$((_n + 1))
            if [ -f "$_file" ] && cmp -s "$_file" "$_file.part"; then
                _current=$((_current + 1))
                rm -f "$_file.part"
            else
                _updated=$((_updated + 1))
                mv -f "$_file.part" "$_file"
            fi
        else
            _n=$((_n + 1))
            fail=1
            rm -f "$_file.part"
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
    # The launcher lives one level up, in Documents: no cd needed to run.
    cat > "$DOCS/barisign" <<'LAUNCHER'
#!/bin/sh
# BariSign launcher — runs from ~/Documents, no cd needed.
cd "$(dirname "$0")/barisign_files" || exit 1
exec python3 -u poc/barisign.py "$@"
LAUNCHER
    chmod +x "$DOCS/barisign" 2>/dev/null
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
works() {
    python3 poc/barisign.py --help >/dev/null 2>&1 \
        && python3 poc/poc_portal.py --help >/dev/null 2>&1 \
        && python3 poc/pair_install.py --check >/dev/null 2>&1 \
        && python3 -c "import sys; sys.path.insert(0, 'poc'); import webui, devmode" \
        && sh -n "$DOCS/barisign"
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
        if [ "${_updated:-0}" -eq 0 ]; then
            printf '  files: all current, nothing to replace\n'
        else
            printf '  files: %d updated, %d current\n' "$_updated" "$_current"
        fi
    else
        printf '\r\033[2K  (1/2) files failed\n'
        printf '  ! could not fetch:\n'
        for _one in $FAILED; do printf '    %s\n' "$_one"; done
    fi

    printf '  (2/2) check ...'
    COMPILE_BAD=""
    if [ "$fail" -eq 0 ] && COMPILE_BAD=$(check_compiles) && works; then
        clear_screen
        break
    fi
    printf '\r\033[2K  (2/2) check failed\n'
    if [ -n "${COMPILE_BAD:-}" ]; then
        printf '  ! does not compile:\n'
        for _one in $COMPILE_BAD; do printf '    %s\n' "$_one"; done
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
printf 'BariSign %s installed\n\n' "${VER:-?}"
printf '  sh barisign\n'
printf '    opens the page, runs the install\n'
printf '  sh barisign help\n'
printf '    every command\n'
