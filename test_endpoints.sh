#!/bin/bash
echo "Building server..."
cargo build --manifest-path native/Cargo.toml

echo "Starting server in background..."
cargo run --manifest-path native/Cargo.toml &
SERVER_PID=$!

echo "Waiting for server to start..."
sleep 5

echo "--- Testing Sandbox & Purple Team Emulator ---"
curl -s -X POST http://127.0.0.1:9090/api/v1/red_team/simulate -H "Content-Type: application/json" -d '{}' | jq

echo ""
echo "--- Testing YARA & Entropy (Analyze Event) ---"
curl -s -X POST http://127.0.0.1:9090/api/v1/analyze_event -H "Content-Type: application/json" -d '{
    "payload": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...",
    "source_ip": "192.168.1.10"
}' | jq

echo ""
echo "--- Testing WebAuthn SQLite Registration (Challenge) ---"
curl -s -X POST http://127.0.0.1:9090/api/v1/auth/challenge -H "Content-Type: application/json" -d '{
    "user_id": "admin"
}' | jq

echo ""
echo "Killing server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null
echo "Tests completed!"
