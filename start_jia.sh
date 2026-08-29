#!/usr/bin/env bash
set -e

echo "🚀 [JIA CYBERSECURITY AGENT] Starting All Services..."
echo "======================================================="

# Build Rust sidecar
echo "🛠️  Building Vella Rust native sidecar engine..."
cd native
cargo build --release || cargo build
cd ..

echo "🛠️  Building Gleam OTP Orchestrator..."
gleam build

echo "======================================================="
echo "✨ Starting Vella Rust Engine on port 9090..."
./native/target/release/jia_native &
NATIVE_PID=$!

# Clean up child process on exit
trap 'kill $NATIVE_PID 2>/dev/null || true' EXIT SIGINT SIGTERM

sleep 2

echo "✨ Running Gleam Agent Orchestrator..."
gleam run || true

echo "======================================================="
echo "✅ Jia AI Security Agent & Dashboard are ONLINE on http://127.0.0.1:9090/dashboard"
echo "   Keeping background server active..."

wait $NATIVE_PID
