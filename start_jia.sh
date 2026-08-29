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
echo "✨ Starting Vella Rust Engine in background on port 9090..."
./native/target/debug/jia_native &
NATIVE_PID=$!

sleep 2

echo "✨ Running Gleam Agent Orchestrator..."
gleam run

kill $NATIVE_PID 2>/dev/null || true
echo "======================================================="
echo "✅ Jia execution complete."
