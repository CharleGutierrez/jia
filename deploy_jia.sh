#!/bin/bash

# Find jia.service
SERVICE_PATH=$(find /etc/systemd/system /lib/systemd/system $HOME/.config/systemd/user -name jia.service 2>/dev/null | head -n 1)

if [ -z "$SERVICE_PATH" ]; then
    echo "jia.service not found!"
    exit 1
fi

echo "Found service at $SERVICE_PATH"

# Extract ExecStart path
EXEC_START=$(grep '^ExecStart=' "$SERVICE_PATH" | cut -d'=' -f2)
echo "ExecStart is $EXEC_START"

# Handle binary replacement
BIN_PATH=$(echo "$EXEC_START" | awk '{print $1}')
if [[ "$BIN_PATH" == *"/usr/local/bin/"* ]]; then
    echo "Copying jia_native to $BIN_PATH"
    cp "/home/cog/Pi Assisted Projects/jia/native/target/release/jia_native" "$BIN_PATH"
else
    echo "ExecStart doesn't point to /usr/local/bin/. It points to $BIN_PATH."
    echo "If it uses start_jia.sh, the binaries are already updated in the workspace."
fi

# Reload and restart
if [[ "$SERVICE_PATH" == *"/user/"* ]]; then
    echo "Restarting user service..."
    systemctl --user daemon-reload
    systemctl --user enable jia.service
    systemctl --user restart jia.service
else
    echo "Restarting system service..."
    systemctl daemon-reload || sudo systemctl daemon-reload
    systemctl enable jia.service || sudo systemctl enable jia.service
    systemctl restart jia.service || sudo systemctl restart jia.service
fi

echo "Jia service updated and restarted!"
