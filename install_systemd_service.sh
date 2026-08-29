#!/usr/bin/env bash
set -e

echo "🚀 [JIA INSTALLER] Integrating Jia as an Automatic Background Protection Service..."
echo "================================================================================"

SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/jia.service"
JIA_DIR="/home/cog/Pi Assisted Projects/jia"

mkdir -p "$SERVICE_DIR"

cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Jia AI Cybersecurity Protection Agent Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=$JIA_DIR
ExecStart=/bin/bash "$JIA_DIR/start_jia.sh"
Restart=always
RestartSec=5s
Environment=PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.cargo/bin:$HOME/.gleam/bin:$HOME/.erlenv/bin

[Install]
WantedBy=default.target
EOF

echo "✅ Created systemd user service at: $SERVICE_FILE"

systemctl --user daemon-reload
systemctl --user enable jia.service
systemctl --user restart jia.service

echo "================================================================================"
echo "✨ Jia is now configured to launch automatically whenever your laptop boots up!"
echo "   Status: Active & Protecting in the Background."
echo "   Dashboard: http://127.0.0.1:9090/dashboard"
echo "================================================================================"
