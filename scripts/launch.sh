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

# Detect Steam Frame environment
IS_STEAM_FRAME=0
if [ "$(hostname 2>/dev/null)" = "frame" ] || grep -q 'VARIANT_ID="vr"' /etc/os-release 2>/dev/null || [ -d "/usr/share/deckard" ] || [ -n "$STEAM_FRAME" ]; then
    IS_STEAM_FRAME=1
fi

if [ "$IS_STEAM_FRAME" -eq 1 ]; then
    export STEAM_FRAME=1
    # On Steam Frame / VR, gamescope runs at 144 DPI Xft.dpi. An internal 1.5x scale multiplier causes
    # double-scaling (~2.25x), zooming in the UI excessively. Default to 1.0 (100%) on the Frame.
    export TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}"
fi

# Detect game executable name from Steam command line arguments if present
GAME_EXE=""
for arg in "$@"; do
    if [[ "$arg" == *.exe ]] || [[ "$arg" == *.x86_64 ]]; then
        GAME_EXE=$(basename "$arg")
        break
    fi
done

if [ -n "$GAMESCOPE_WAYLAND_DISPLAY" ] || [ -n "$STEAM_DECK" ] || [ -n "$SteamGamepadUI" ]; then
    export TRAINLAB_GAMESCOPE=1
fi

AUTO_ARGS="--auto-attach --no-fullscreen --hidden --auto-exit"
if [ -n "$GAME_EXE" ]; then
    AUTO_ARGS="$AUTO_ARGS --game $GAME_EXE"
fi
if [ -n "$TRAINLAB_SCALE" ]; then
    AUTO_ARGS="$AUTO_ARGS --scale $TRAINLAB_SCALE"
fi
export TRAINLAB_AUTO_INJECT=1
export TRAINLAB_HIDDEN=1
export TRAINLAB_AUTO_EXIT=1

# Single-instance companion lock:
# Steam / Proton invokes launch wrappers once per process in the game's launch hierarchy.
# Only the primary instance holding the lock will spawn trainlab and manage its lifecycle.
LOCK_ID="${GAME_EXE:-app}"
LOCK_ID=$(echo "$LOCK_ID" | tr -c '[:alnum:]_.-' '_')
LOCK_FILE="/tmp/trainlab-${LOCK_ID}.lock"

SPAWN_TRAINER=0
exec 200>"$LOCK_FILE"
if flock -n 200; then
    SPAWN_TRAINER=1
    echo "$$" >&200
    echo "[trainlab] Acquired companion lock on $LOCK_FILE (PID $$)" >>/tmp/trainlab_launch_out.log
else
    echo "[trainlab] Companion lock on $LOCK_FILE already held; skipping secondary trainer launch for PID $$" >>/tmp/trainlab_launch_out.log
fi

# 1. Execute the main game launch in the background and capture its PID
"$@" 200>&- &
GAME_PID=$!

TRAINER_PID=""
GUARDIAN_PID=""

# 2. Launch Trainlab GUI only if this instance holds the primary companion lock
if [ "$SPAWN_TRAINER" -eq 1 ]; then
    # Wait 4 seconds for game window / container initialization in Gamescope
    sleep 4

    # 3. Launch Trainlab GUI in the background according to runtime environment
    if [ -n "$PROTON_RUNNER" ] && [ -x "$PROTON_RUNNER" ] && [ -n "$TARGET_WIN_EXE" ]; then
        echo "[trainlab] Launching Windows trainer via Proton: $PROTON_RUNNER ($TARGET_WIN_EXE $AUTO_ARGS)" >>/tmp/trainlab_launch_out.log
        # Scrub Steam AppID, LD_PRELOAD (to avoid 32-bit gameoverlayrenderer mismatch), and client launch env
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$PROTON_RUNNER" run "$TARGET_WIN_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        TRAINER_PID=$!
    elif [ -n "$SLR_ENTRY" ] && [ -x "$SLR_ENTRY" ] && [ -n "$TARGET_LINUX_EXE" ]; then
        echo "[trainlab] Launching native Linux trainer inside SLR container: $SLR_ENTRY ($TARGET_LINUX_EXE $AUTO_ARGS)" >>/tmp/trainlab_launch_out.log
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$SLR_ENTRY" --verb=run -- "$TARGET_LINUX_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        TRAINER_PID=$!
    elif [ -n "$TARGET_LINUX_EXE" ]; then
        echo "[trainlab] Launching native Linux trainer directly on host ($TARGET_LINUX_EXE $AUTO_ARGS)" >>/tmp/trainlab_launch_out.log
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$TARGET_LINUX_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        TRAINER_PID=$!
    elif [ -n "$TARGET_WIN_EXE" ]; then
        echo "[trainlab] WARNING: Only Windows trainer exists but no Proton runner detected." >>/tmp/trainlab_launch_out.log
    else
        echo "[trainlab] WARNING: No trainlab or trainlab.exe executable found in $TRAINLAB_DIR" >>/tmp/trainlab_launch_out.log
    fi

    # Proactive Gamescope & X11 capture guardian:
    # 1. Strips any inherited STEAM_GAME atom from trainlab windows so Gamescope never latches onto it as the stream base layer.
    # 2. In Gamescope mode when hidden, unmaps the window so Gamescope never treats it as a capture candidate.
    # 3. Ensures window focus remains firmly with the game window.
    (
        for i in $(seq 1 30); do
            sleep 1
            for disp in :0 :1; do
                if [ -S "/tmp/.X11-unix/X${disp#:}" ]; then
                    TL_WINS=$(DISPLAY="$disp" xdotool search --name trainlab 2>/dev/null || true)
                    TL_CLASS_WINS=$(DISPLAY="$disp" xdotool search --class trainlab 2>/dev/null || true)
                    for wid in $TL_WINS $TL_CLASS_WINS; do
                        if [ -n "$wid" ]; then
                            DISPLAY="$disp" xprop -id "$wid" -remove STEAM_GAME 2>/dev/null || true
                            if [ "${TRAINLAB_GAMESCOPE:-0}" = "1" ] || [ "${TRAINLAB_HIDDEN:-0}" = "1" ]; then
                                DISPLAY="$disp" xdotool windowunmap "$wid" 2>/dev/null || true
                            fi
                        fi
                    done
                fi
            done

            # Reassert focus on the game window if available
            if [ -n "$GAME_EXE" ]; then
                for disp in :0 :1; do
                    if [ -S "/tmp/.X11-unix/X${disp#:}" ]; then
                        DISPLAY="$disp" xdotool search --name "$GAME_EXE" windowactivate 2>/dev/null || true
                    fi
                done
            fi
        done
    ) 200>&- &
    GUARDIAN_PID=$!
fi

# 4. Cleanup routine to tear down companion trainer processes
cleanup() {
    # If this invocation did not acquire the companion lock, forward signal to GAME_PID and exit
    if [ "$SPAWN_TRAINER" -ne 1 ]; then
        if [ -n "$GAME_PID" ] && kill -0 "$GAME_PID" 2>/dev/null; then
            kill -TERM "$GAME_PID" 2>/dev/null
        fi
        return
    fi

    # 1. If the game process is still alive when cleanup is invoked (e.g. SIGTERM/INT from Steam),
    # forward SIGTERM first and grant a grace period so the injected library's signal handler
    # can run render::shutdown() and restore original Present bytes cleanly.
    if [ -n "$GAME_PID" ] && kill -0 "$GAME_PID" 2>/dev/null; then
        kill -TERM "$GAME_PID" 2>/dev/null
        for _ in $(seq 1 15); do
            if ! kill -0 "$GAME_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        # If the game is still alive after grace period, terminate forcefully
        if kill -0 "$GAME_PID" 2>/dev/null; then
            kill -9 "$GAME_PID" 2>/dev/null
        fi
    fi

    # 2. Reap guardian background worker
    if [ -n "$GUARDIAN_PID" ]; then
        kill "$GUARDIAN_PID" 2>/dev/null
    fi

    # 3. Promptly terminate all Trainlab GUI and helper processes to ensure zero lingering D3D devices
    if [ -n "$TRAINER_PID" ]; then
        kill -TERM "$TRAINER_PID" 2>/dev/null
    fi
    pkill -TERM -f trainlab-gui.exe 2>/dev/null
    pkill -TERM -f trainlab.exe 2>/dev/null
    pkill -TERM -f trainlab-gui-linux 2>/dev/null
    pkill -TERM -x trainlab 2>/dev/null
    sleep 0.2
    if [ -n "$TRAINER_PID" ]; then
        kill -9 "$TRAINER_PID" 2>/dev/null
    fi
    pkill -9 -f trainlab-gui.exe 2>/dev/null
    pkill -9 -f trainlab.exe 2>/dev/null
    pkill -9 -f trainlab-gui-linux 2>/dev/null
    pkill -9 -x trainlab 2>/dev/null

    # 4. Release and remove lock
    flock -u 200 2>/dev/null || true
    exec 200>&-
    rm -f "$LOCK_FILE" 2>/dev/null
}

trap cleanup EXIT INT TERM HUP

# 5. Monitor game process: wait on GAME_PID or exit if the game process disappears
wait "$GAME_PID" 2>/dev/null

# 6. Run cleanup explicitly upon exit
cleanup

