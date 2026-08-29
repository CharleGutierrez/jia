import subprocess
import time
import urllib.request
import json

def request(url, payload=None, method="POST"):
    req = urllib.request.Request(url, method=method)
    req.add_header('Content-Type', 'application/json')
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    try:
        with urllib.request.urlopen(req, data=data) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode()) if e.read() else {}

def run_tests():
    print("Starting cargo run...")
    server = subprocess.Popen(["cargo", "run"], cwd=".", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Wait for build and startup

    base_url = "http://127.0.0.1:9090/api/v1"
    
    try:
        # 1. Detonation Sandbox (via red_team_simulate)
        print("Testing Detonation Sandbox...")
        status, data = request(f"{base_url}/red_team/simulate", {})
        assert status == 200, f"Expected 200, got {status}"
        assert data.get("total_simulations", 0) > 0, "No simulations ran"

        # 2. YARA & Entropy (via analyze_event)
        print("Testing YARA Engine...")
        status, data = request(f"{base_url}/analyze_event", {"payload": "eval($_POST)", "source_ip": "1.1.1.1"})
        assert status == 200
        assert data.get("zero_day_detected") == True
        details = data.get("zero_day_details", "")
        assert "YARA Match" in details or "eval" in details or "PHP" in details or "Shellcode" in details or "ZERO-DAY DETECTED" in details, f"Unexpected details: {details}"

        # 3. WebAuthn DB Persistence (via challenge)
        print("Testing WebAuthn Challenge...")
        status, ch_data = request(f"{base_url}/auth/challenge", {"user_id": "admin", "rp_id": "jia.security"})
        assert status == 200
        ch_id = ch_data.get("challenge_id")
        assert ch_id, "Missing challenge_id"

        print("Testing WebAuthn Verification Rejection...")
        verify_payload = {
            "challenge_id": ch_id,
            "challenge": ch_data["challenge"],
            "client_data_json": "e30=",
            "authenticator_data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "signature": "AAAA",
            "user_id": "admin"
        }
        status, vf_data = request(f"{base_url}/auth/verify", verify_payload)
        assert status == 401, f"Expected 401, got {status}"

        # 4. eBPF Interception
        print("Testing eBPF Interception...")
        status, ebpf_data = request(f"{base_url}/ebpf/inspect", {"syscall": "execve", "pid": 123, "uid": 0, "path_or_target": "/tmp/privesc"})
        assert status == 200
        assert ebpf_data.get("allowed") == False
        assert ebpf_data.get("threat_detected") == True

        # 5. PQC Telemetry Sign
        print("Testing PQC Sign...")
        status, pqc_data = request(f"{base_url}/pqc/sign", {"log_entry": "test entry"})
        assert status == 200
        assert pqc_data.get("verified") == True

        print("All API integration tests passed successfully!")
    finally:
        server.terminate()
        server.wait()

if __name__ == "__main__":
    run_tests()
