#!/usr/bin/env bash
# ==============================================================================
# Trainlab Steam Launch Wrapper
# ==============================================================================
# Usage in Steam Launch Options:
#   /home/deck/Documents/Trainers/Trainlab/launch.sh %command%
#
# Behavior:
#   1. Starts the target game with all original Steam/Proton command line args ($@)
#   2. Identifies the exact Proton binary invoked by Steam in $@
#   3. Launches trainlab-gui.exe in the same Proton runner and prefix
#   4. Monitors the game process; upon exit, cleanly terminates trainlab-gui.exe
# ==============================================================================

# Extract the exact Proton runner invoked in Steam's command ($@)
PROTON_RUNNER=""
for arg in "$@"; do
    if [[ "$arg" == *"proton" ]] && [ -x "$arg" ]; then
        PROTON_RUNNER="$arg"
        break
    fi
done

# Fallback to RUNPROTON environment or latest installed Proton if not found in args
if [ -z "$PROTON_RUNNER" ]; then
    if [ -n "$RUNPROTON" ] && [ -x "$RUNPROTON" ]; then
        PROTON_RUNNER="$RUNPROTON"
    else
        PROTON_RUNNER="$(find "$HOME/.local/share/Steam/steamapps/common/" -maxdepth 2 -name proton 2>/dev/null | sort -V | tail -n1)"
    fi
fi

# 1. Execute the main game launch in the background and capture its PID
"$@" &
GAME_PID=$!

# 2. Wait 4 seconds for game window / Proton prefix initialization in Gamescope
sleep 4

# 3. Launch Trainlab GUI under Proton in the background and capture its PID
TRAINLAB_DIR="${TRAINLAB_DIR:-$HOME/Documents/Trainers/Trainlab}"
TARGET_EXE="$TRAINLAB_DIR/trainlab-gui.exe"
TRAINER_PID=""

if [ -f "$TARGET_EXE" ] && [ -n "$PROTON_RUNNER" ] && [ -x "$PROTON_RUNNER" ]; then
    "$PROTON_RUNNER" run "$TARGET_EXE" >/tmp/trainlab_launch_out.log 2>&1 &
    TRAINER_PID=$!
fi

# 4. Cleanup routine to aggressively tear down all child/helper processes
cleanup() {
    # Terminate Trainlab GUI
    if [ -n "$TRAINER_PID" ]; then
        kill -9 "$TRAINER_PID" 2>/dev/null
    fi
    pkill -9 -f trainlab-gui.exe 2>/dev/null

    # If the game process is still alive when cleanup is triggered (e.g. Steam Stop button)
    if [ -n "$GAME_PID" ] && kill -0 "$GAME_PID" 2>/dev/null; then
        kill -9 "$GAME_PID" 2>/dev/null
    fi

    # Terminate any orphaned Wine helper processes left behind in this session
    pkill -9 -f xalia.exe 2>/dev/null
    pkill -9 -f tabtip.exe 2>/dev/null
    pkill -9 -f explorer.exe 2>/dev/null
    pkill -9 -f winedevice.exe 2>/dev/null
    pkill -9 -f services.exe 2>/dev/null
    pkill -9 -f plugplay.exe 2>/dev/null
    pkill -9 -f rpcss.exe 2>/dev/null
}

trap cleanup EXIT INT TERM HUP

# 5. Monitor game process: wait on GAME_PID or exit if the game process disappears
wait "$GAME_PID" 2>/dev/null

# 6. Run cleanup explicitly upon exit
cleanup
