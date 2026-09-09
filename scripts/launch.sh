#!/usr/bin/env bash
# ==============================================================================
# Trainlab Steam Launch Wrapper
# ==============================================================================
# Usage in Steam Launch Options:
#   /home/<user>/Documents/Trainers/Trainlab/launch.sh %command%
#
# Behavior:
#   1. Starts the target game with all original Steam/Proton command line args ($@)
#   2. Identifies the exact Proton binary invoked by Steam in $@
#   3. Launches trainlab-gui.exe in the same Proton runner and prefix
#   4. Monitors the game process; upon exit, cleanly terminates trainlab-gui.exe
#
# Compatibility:
#   Works on any Linux distro with Steam installed natively or via Flatpak.
# ==============================================================================

# Detect launch environment: Proton, Steam Linux Runtime (SLR/pressure-vessel), or native Linux
PROTON_RUNNER=""
SLR_ENTRY=""

# 1. Search for Proton runner first. Modern Proton (e.g. Proton 8, 9, 10, 11) runs inside
# Steam Linux Runtime containers (e.g. SteamLinuxRuntime_4, soldier, sniper).
# Steam passes both `_v2-entry-point` AND `/path/to/Proton/proton` in $@.
# If Proton is present, it MUST take precedence so we launch trainlab.exe under Proton!
for arg in "$@"; do
    if [[ "$arg" == *"proton" ]] && [ -x "$arg" ]; then
        PROTON_RUNNER="$arg"
        break
    fi
done

# 2. Only look for SLR container if Proton was NOT found (meaning a native Linux game)
if [ -z "$PROTON_RUNNER" ]; then
    for arg in "$@"; do
        if [[ "$arg" == *"_v2-entry-point" ]] && [ -x "$arg" ]; then
            SLR_ENTRY="$arg"
            break
        elif [[ "$arg" == *"pressure-vessel-adverb"* ]] && [ -x "$arg" ]; then
            SLR_ENTRY="$arg"
            break
        fi
    done
fi

TRAINLAB_DIR="${TRAINLAB_DIR:-$HOME/Documents/Trainers/Trainlab}"

# Check for unified names first, then legacy names
TARGET_WIN_EXE=""
if [ -f "$TRAINLAB_DIR/trainlab.exe" ]; then
    TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab.exe"
elif [ -f "$TRAINLAB_DIR/trainlab-gui.exe" ]; then
    TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab-gui.exe"
fi

TARGET_LINUX_EXE=""
if [ -f "$TRAINLAB_DIR/trainlab" ]; then
    TARGET_LINUX_EXE="$TRAINLAB_DIR/trainlab"
elif [ -f "$TRAINLAB_DIR/trainlab-gui-linux" ]; then
    TARGET_LINUX_EXE="$TRAINLAB_DIR/trainlab-gui-linux"
elif [ -f "$TRAINLAB_DIR/trainlab-gui" ]; then
    TARGET_LINUX_EXE="$TRAINLAB_DIR/trainlab-gui"
fi

if [ -z "$PROTON_RUNNER" ] && [ -z "$SLR_ENTRY" ]; then
    echo "[trainlab] INFO: No Proton runner or SLR container detected in launch command. Assuming native Linux host." >/tmp/trainlab_launch_out.log
fi

# 1. Execute the main game launch in the background and capture its PID
"$@" &
GAME_PID=$!

# 2. Wait 4 seconds for game window / container initialization in Gamescope
sleep 4

# 3. Launch Trainlab GUI in the background according to runtime environment
TRAINER_PID=""

if [ -n "$PROTON_RUNNER" ] && [ -x "$PROTON_RUNNER" ] && [ -n "$TARGET_WIN_EXE" ]; then
    echo "[trainlab] Launching Windows trainer via Proton: $PROTON_RUNNER ($TARGET_WIN_EXE)" >>/tmp/trainlab_launch_out.log
    "$PROTON_RUNNER" run "$TARGET_WIN_EXE" >>/tmp/trainlab_launch_out.log 2>&1 &
    TRAINER_PID=$!
elif [ -n "$SLR_ENTRY" ] && [ -x "$SLR_ENTRY" ] && [ -n "$TARGET_LINUX_EXE" ]; then
    echo "[trainlab] Launching native Linux trainer inside SLR container: $SLR_ENTRY ($TARGET_LINUX_EXE)" >>/tmp/trainlab_launch_out.log
    "$SLR_ENTRY" --verb=run -- "$TARGET_LINUX_EXE" >>/tmp/trainlab_launch_out.log 2>&1 &
    TRAINER_PID=$!
elif [ -n "$TARGET_LINUX_EXE" ]; then
    echo "[trainlab] Launching native Linux trainer directly on host ($TARGET_LINUX_EXE)" >>/tmp/trainlab_launch_out.log
    "$TARGET_LINUX_EXE" >>/tmp/trainlab_launch_out.log 2>&1 &
    TRAINER_PID=$!
elif [ -n "$TARGET_WIN_EXE" ]; then
    echo "[trainlab] WARNING: Only Windows trainer exists but no Proton runner detected." >>/tmp/trainlab_launch_out.log
else
    echo "[trainlab] WARNING: No trainlab or trainlab.exe executable found in $TRAINLAB_DIR" >>/tmp/trainlab_launch_out.log
fi

# 4. Cleanup routine to aggressively tear down all child/helper processes
cleanup() {
    # Terminate Trainlab GUI
    if [ -n "$TRAINER_PID" ]; then
        kill -9 "$TRAINER_PID" 2>/dev/null
    fi
    pkill -9 -f trainlab-gui.exe 2>/dev/null
    pkill -9 -f trainlab.exe 2>/dev/null
    pkill -9 -f trainlab-gui-linux 2>/dev/null
    pkill -9 -x trainlab 2>/dev/null

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
