#!/usr/bin/env bash

# 1. Execute the main game launch in the background and save its PID
"$@" &
GAME_PID=$!

# 2. Wait 4 seconds for Helldivers window to initialize in Gamescope
sleep 4

# 3. Launch Trainlab GUI under Proton in the background and save its PID
PROTON_BIN="$(find ~/.local/share/Steam/steamapps/common/ -maxdepth 2 -name proton | tail -n1)"
TRAINER_PID=""
if [ -n "$PROTON_BIN" ]; then
    "$PROTON_BIN" run /home/deck/Documents/Trainers/Trainlab/trainlab-gui.exe >/tmp/trainlab_launch_out.log 2>&1 &
    TRAINER_PID=$!
fi

# 4. Wait for the main game process (Helldivers) to exit
wait "$GAME_PID"

# 5. Automatically kill Trainlab GUI process when game exits so Steam exits cleanly
if [ -n "$TRAINER_PID" ]; then
    kill -9 "$TRAINER_PID" 2>/dev/null
fi
pkill -9 -f trainlab-gui.exe 2>/dev/null
