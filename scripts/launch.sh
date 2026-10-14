#!/usr/bin/env bash
# ==============================================================================
# Trainlab Steam Launch Wrapper
# ==============================================================================
# Usage in Steam Launch Options:
#   /home/<user>/Documents/Trainers/Trainlab/launch.sh %command%
#
# Behavior:
#   1. Starts the target game with all original Steam/Proton command line args
#   2. Launches trainlab in the same Proton runner and prefix
#   3. Waits for the game process to exit; trainlab manages its own lifecycle
#      via --auto-exit (watches for the game process to disappear)
#
# Each process handles its own cleanup. Steam/Proton can kill either process
# independently — no parent watcher or kill cascade is needed.
# ==============================================================================

LOG="/tmp/trainlab_launch_out.log"
log() { echo "[trainlab][$(date '+%Y-%m-%d %H:%M:%S')] $*" >>"$LOG"; }

# Detect launch environment: Proton, Steam Linux Runtime (SLR/pressure-vessel), or native Linux
PROTON_RUNNER=""
for arg in "$@"; do
    if [[ "$arg" == *"proton" ]] && [ -x "$arg" ]; then
        PROTON_RUNNER="$arg"
        break
    fi
done

SLR_ENTRY=""
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

# Detect game executable name and path from Steam command line arguments
GAME_EXE=""
GAME_EXE_PATH=""
for arg in "$@"; do
    if [[ "$arg" == *.exe ]] || [[ "$arg" == *.x86_64 ]]; then
        GAME_EXE=$(basename "$arg")
        GAME_EXE_PATH="$arg"
        break
    fi
done

# Detect whether game executable is 32-bit x86 (e.g. DREDGE) or 64-bit x86-64
IS_32BIT=0
if [ -n "$GAME_EXE_PATH" ] && [ -f "$GAME_EXE_PATH" ]; then
    if command -v file >/dev/null 2>&1; then
        if file -b "$GAME_EXE_PATH" 2>/dev/null | grep -qi "PE32 .*Intel 80386"; then
            IS_32BIT=1
        fi
    fi
    if [ "$IS_32BIT" -eq 0 ] && command -v od >/dev/null 2>&1; then
        pe_offset=$(od -An -j 60 -N 4 -t u4 "$GAME_EXE_PATH" 2>/dev/null | tr -d ' ')
        if [ -n "$pe_offset" ] && [ "$pe_offset" -gt 0 ] 2>/dev/null; then
            machine=$(od -An -j "$((pe_offset + 4))" -N 2 -t x2 "$GAME_EXE_PATH" 2>/dev/null | tr -d ' ')
            if [ "$machine" = "014c" ]; then
                IS_32BIT=1
            fi
        fi
    fi
fi

TARGET_WIN_EXE=""
TARGET_WIN_DLL=""
if [ "$IS_32BIT" -eq 1 ]; then
    log "Detected 32-bit game executable ($GAME_EXE)"
    if [ -f "$TRAINLAB_DIR/trainlab32.exe" ]; then
        TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab32.exe"
    elif [ -f "$TRAINLAB_DIR/trainlab.exe" ]; then
        TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab.exe"
    fi
    if [ -f "$TRAINLAB_DIR/trainlab32.dll" ]; then
        TARGET_WIN_DLL="$TRAINLAB_DIR/trainlab32.dll"
    elif [ -f "$TRAINLAB_DIR/trainlab.dll" ]; then
        TARGET_WIN_DLL="$TRAINLAB_DIR/trainlab.dll"
    fi
else
    log "Detected 64-bit game executable ($GAME_EXE)"
    if [ -f "$TRAINLAB_DIR/trainlab.exe" ]; then
        TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab.exe"
    elif [ -f "$TRAINLAB_DIR/trainlab-gui.exe" ]; then
        TARGET_WIN_EXE="$TRAINLAB_DIR/trainlab-gui.exe"
    fi
    if [ -f "$TRAINLAB_DIR/trainlab.dll" ]; then
        TARGET_WIN_DLL="$TRAINLAB_DIR/trainlab.dll"
    fi
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
    log "No Proton runner or SLR container detected; assuming native Linux host"
fi

# Detect Steam Frame environment
IS_STEAM_FRAME=0
if [ "$(hostname 2>/dev/null)" = "frame" ] || grep -q 'VARIANT_ID="vr"' /etc/os-release 2>/dev/null || [ -d "/usr/share/deckard" ] || [ -n "$STEAM_FRAME" ]; then
    IS_STEAM_FRAME=1
    export STEAM_FRAME=1
    export TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}"
fi

if [ -n "$GAMESCOPE_WAYLAND_DISPLAY" ] || [ -n "$STEAM_DECK" ] || [ -n "$SteamGamepadUI" ]; then
    export TRAINLAB_GAMESCOPE=1
fi

AUTO_ARGS="--auto-attach --no-fullscreen --hidden --auto-exit"
if [ -n "$GAME_EXE" ]; then
    AUTO_ARGS="$AUTO_ARGS --game $GAME_EXE"
fi
if [ -n "$TARGET_WIN_DLL" ]; then
    AUTO_ARGS="$AUTO_ARGS --dll $TARGET_WIN_DLL"
fi
if [ -n "$TRAINLAB_SCALE" ]; then
    AUTO_ARGS="$AUTO_ARGS --scale $TRAINLAB_SCALE"
fi
export TRAINLAB_AUTO_INJECT=1
export TRAINLAB_HIDDEN=1
export TRAINLAB_AUTO_EXIT=1

# Single-instance companion lock: only one launch.sh instance spawns trainlab per game
LOCK_ID=$(echo "${GAME_EXE:-app}" | tr -c '[:alnum:]_.-' '_')
LOCK_FILE="/tmp/trainlab-${LOCK_ID}.lock"
SPAWN_TRAINER=0
exec 200>"$LOCK_FILE"
if flock -n 200; then
    SPAWN_TRAINER=1
    echo "$$" >&200
    log "Acquired companion lock on $LOCK_FILE (PID $$, game=$GAME_EXE)"
else
    log "Lock held; skipping trainer launch for PID $$"
fi

cleanup() {
    flock -u 200 2>/dev/null || true
    exec 200>&-
    rm -f "$LOCK_FILE" 2>/dev/null
}
trap cleanup EXIT

# 1. Launch the game
"$@" 200>&- &
GAME_PID=$!
log "Game started (PID $GAME_PID, runner=${PROTON_RUNNER:-native})"

# 2. Launch trainlab companion (only if we hold the lock)
if [ "$SPAWN_TRAINER" -eq 1 ]; then
    sleep 4

    if [ -n "$PROTON_RUNNER" ] && [ -x "$PROTON_RUNNER" ] && [ -n "$TARGET_WIN_EXE" ]; then
        log "Launching trainlab via Proton: $TARGET_WIN_EXE (LIBGL_ALWAYS_SOFTWARE=1, audio=disabled)"
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            WINEDLLOVERRIDES="winepulse.drv=d;winealsa.drv=d;mmdevapi=d" \
            WINELOADERNOEXEC=1 \
            LIBGL_ALWAYS_SOFTWARE=1 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$PROTON_RUNNER" run "$TARGET_WIN_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        log "Trainlab companion started (PID $!)"
    elif [ -n "$SLR_ENTRY" ] && [ -x "$SLR_ENTRY" ] && [ -n "$TARGET_LINUX_EXE" ]; then
        log "Launching trainlab in SLR container: $TARGET_LINUX_EXE"
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$SLR_ENTRY" --verb=run -- "$TARGET_LINUX_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        log "Trainlab companion started (PID $!)"
    elif [ -n "$TARGET_LINUX_EXE" ]; then
        log "Launching native trainlab: $TARGET_LINUX_EXE"
        env -u LD_PRELOAD -u SteamAppId -u SteamGameId -u STEAM_COMPAT_APP_ID -u SteamClientLaunch \
            SteamAppId=0 SteamGameId=0 \
            TRAINLAB_GAMESCOPE="${TRAINLAB_GAMESCOPE:-0}" TRAINLAB_AUTO_INJECT=1 TRAINLAB_AUTO_EXIT=1 TRAINLAB_SCALE="${TRAINLAB_SCALE:-1.0}" \
            "$TARGET_LINUX_EXE" $AUTO_ARGS 200>&- >>/tmp/trainlab_launch_out.log 2>&1 &
        log "Trainlab companion started (PID $!)"
    elif [ -n "$TARGET_WIN_EXE" ]; then
        log "WARNING: Only Windows trainer exists but no Proton runner detected"
    else
        log "WARNING: No trainlab executable found in $TRAINLAB_DIR"
    fi
fi

# 3. Wait for the game to exit — trainlab self-exits via --auto-exit
wait "$GAME_PID" 2>/dev/null
log "Game exited (code $?)"
