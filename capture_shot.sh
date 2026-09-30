#!/usr/bin/env bash
# capture_shot.sh - open a terminal on the Kali workstation, run a command
# against the target, and screenshot the window.
#
# WHY THIS EXISTS
# The instructor's evidence list requires screenshots. Every artifact captured
# so far was text. Text proves the claims but is not what was asked for.
#
# This captures a REAL terminal window on the attacker workstation showing the
# REAL command and its REAL output from the target. Nothing is synthesised:
# the window is not drawn by a renderer, it is a live qterminal session and
# the pixels come from `import -window <id>`.
#
# Usage:
#   ./capture_shot.sh OUT.png "Window Title" "shell command to run" [wait_secs]
set -uo pipefail

OUT="${1:?output png}"
TITLE="${2:?window title}"
CMD="${3:?command}"
WAIT="${4:-6}"

# A unique token so we can find *our* window and not someone else's.

# Start from a clean slate: any leftover terminal from a previous run would
# otherwise be picked up and screenshotted instead of this one.
pkill -9 -f qterminal >/dev/null 2>&1 </dev/null || true
sleep 1

qterminal --title "${TITLE}" -e bash -lc "$CMD; echo; echo '[window will close shortly]'; sleep 4" \
    >/dev/null 2>&1 </dev/null &
QTPID=$!
disown "$QTPID" 2>/dev/null

# Identify our window by CLASS, choosing the largest one. QTerminal creates
# several 10x10 utility windows, and its title changes once the command runs,
# so title-based lookup and first-match lookup are both unreliable.
WIN=""
BEST_AREA=0
for _ in $(seq 1 60); do
    for w in $(xdotool search --class qterminal 2>/dev/null); do
        g=$(xdotool getwindowgeometry "$w" 2>/dev/null | awk '/Geometry/{print $2}')
        case "$g" in
            *x*) ;;
            *) continue ;;
        esac
        area=$(( ${g%x*} * ${g#*x} ))
        if [ "$area" -gt "$BEST_AREA" ]; then
            BEST_AREA=$area
            WIN="$w"
        fi
    done
    [ "$BEST_AREA" -gt 100000 ] && break
    sleep 0.25
done

if [ -z "$WIN" ] || [ "$BEST_AREA" -le 100000 ]; then
    echo "FAILED: no usable qterminal window (best area=$BEST_AREA)" >&2
    exit 1
fi

# Give the shell time to paint, then size the window to fill the screen so
# long output is not cut off.
sleep 1
xdotool windowsize "$WIN" 1900 1040 2>/dev/null
xdotool windowmove "$WIN" 10 20 2>/dev/null
xdotool windowactivate "$WIN" 2>/dev/null
sleep "$WAIT"

# Capture just this window. Never fall back to the whole root window: the
# workstation desktop holds unrelated private apps.
import -window "$WIN" "$OUT" >/dev/null 2>&1

xdotool windowkill "$WIN" 2>/dev/null
kill "$QTPID" 2>/dev/null
wait "$QTPID" 2>/dev/null

if [ -s "$OUT" ]; then
    echo "OK   $OUT  $(identify -format '%wx%h' "$OUT" 2>/dev/null)"
else
    echo "FAIL $OUT (empty or missing)" >&2
    exit 1
fi
