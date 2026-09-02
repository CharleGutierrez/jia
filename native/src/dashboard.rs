use axum::response::Html;

pub fn render_dashboard() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jia Cyber Command Center</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #070a12;
            --bg-card: rgba(14, 21, 37, 0.75);
            --bg-card-hover: rgba(20, 30, 52, 0.85);
            --border-cyan: rgba(0, 240, 255, 0.35);
            --neon-cyan: #00f0ff;
            --neon-green: #00ff66;
            --neon-red: #ff3366;
            --neon-purple: #a855f7;
            --neon-amber: #f59e0b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            background-image: 
                radial-gradient(at 0% 0%, rgba(0, 240, 255, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.12) 0px, transparent 50%);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            padding: 24px;
        }

        h1, h2, h3, h4, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Header Glass Banner */
        .header-banner {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-cyan);
            border-radius: 16px;
            padding: 20px 30px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45);
        }

        .title-group h1 {
            font-size: 1.8rem;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #00f0ff, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .title-group p {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 4px;
        }

        .status-badge {
            background: rgba(0, 255, 102, 0.12);
            border: 1px solid rgba(0, 255, 102, 0.4);
            color: var(--neon-green);
            padding: 8px 16px;
            border-radius: 30px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            background-color: var(--neon-green);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--neon-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 102, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(0, 255, 102, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 102, 0); }
        }

        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 20px;
        }

        .glass-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 20px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 20px 0 rgba(0, 0, 0, 0.3);
        }

        .glass-card:hover {
            border-color: var(--border-cyan);
            background: var(--bg-card-hover);
        }

        .col-12 { grid-column: span 12; }
        .col-6 { grid-column: span 6; }
        .col-4 { grid-column: span 4; }
        .col-8 { grid-column: span 8; }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 10px;
        }

        .card-header h3 {
            font-size: 1.05rem;
            color: var(--neon-cyan);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Node Stats */
        .cluster-node-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }

        .node-box {
            background: rgba(10, 15, 26, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px;
        }

        .node-title {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .node-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.15rem;
            font-weight: 700;
            margin-top: 4px;
        }

        /* Form Controls */
        input[type="text"], textarea, select {
            width: 100%;
            background: rgba(7, 10, 18, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text-main);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.2s;
            margin-bottom: 10px;
        }

        input[type="text"]:focus, textarea:focus, select:focus {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.25);
        }

        button {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(168, 85, 247, 0.2));
            border: 1px solid var(--neon-cyan);
            color: var(--text-main);
            padding: 10px 18px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        button:hover {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.4), rgba(168, 85, 247, 0.4));
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.4);
            transform: translateY(-1px);
        }

        .output-box {
            background: rgba(5, 7, 13, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            max-height: 180px;
            overflow-y: auto;
            color: var(--neon-green);
            white-space: pre-wrap;
        }

        /* Waterfall Live Feed */
        .waterfall-feed {
            max-height: 220px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .feed-item {
            background: rgba(10, 15, 26, 0.6);
            border-left: 3px solid var(--neon-cyan);
            border-radius: 4px 8px 8px 4px;
            padding: 8px 12px;
            font-size: 0.82rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .feed-item.critical { border-left-color: var(--neon-red); }
        .feed-item.high { border-left-color: var(--neon-amber); }
        .feed-item.low { border-left-color: var(--neon-green); }

        /* MITRE ATT&CK Matrix Grid */
        .mitre-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 8px;
        }

        .mitre-cell {
            background: rgba(10, 15, 26, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 6px;
            padding: 10px;
            font-size: 0.75rem;
            transition: all 0.2s ease;
        }

        .mitre-cell.active {
            border-color: var(--neon-red);
            background: rgba(255, 51, 102, 0.15);
            box-shadow: 0 0 8px rgba(255, 51, 102, 0.3);
        }

        .mitre-cell-title {
            font-weight: 700;
            color: var(--neon-cyan);
            margin-bottom: 4px;
        }

        .mitre-cell-tech {
            color: var(--text-muted);
            font-size: 0.7rem;
        }

        /* Attack Graph Canvas */
        #attack-canvas {
            width: 100%;
            height: 180px;
            background: rgba(5, 7, 13, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }
    </style>
</head>
<body>
    <div class="header-banner">
        <div class="title-group">
            <h1>🛡️ JIA CYBER COMMAND CENTER</h1>
            <p>Gleam (Erlang/BEAM OTP Actor Cluster) & Vella (Rust Native Post-Quantum Defense Engine)</p>
        </div>
        <div class="status-badge">
            <div class="pulse-dot"></div>
            <span id="system-status-text">SYSTEM OPERATIONAL | OTP SUPERVISED</span>
        </div>
    </div>

    <div class="dashboard-grid">
        <!-- Node Cluster & Health Card -->
        <div class="glass-card col-12">
            <div class="card-header">
                <h3>⚡ Node Cluster & Runtime Telemetry</h3>
                <span class="mono" style="font-size: 0.8rem; color: var(--text-muted);" id="uptime-display">Uptime: 0s</span>
            </div>
            <div class="cluster-node-grid">
                <div class="node-box">
                    <div class="node-title">Erlang BEAM Actor Node</div>
                    <div class="node-value" style="color: var(--neon-cyan);">jia@beam-daemon</div>
                    <div style="font-size: 0.75rem; color: var(--neon-green); margin-top: 4px;">● OTP Supervisor Tree Online</div>
                </div>
                <div class="node-box">
                    <div class="node-title">Rust Native Sidecar</div>
                    <div class="node-value" style="color: var(--neon-purple);">http://127.0.0.1:9090</div>
                    <div style="font-size: 0.75rem; color: var(--neon-green); margin-top: 4px;">● Axum + Vella Engine</div>
                </div>
                <div class="node-box">
                    <div class="node-title">WORM Audit Chain Logs</div>
                    <div class="node-value" id="worm-count-val" style="color: var(--neon-green);">0 Entries</div>
                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">Merkle Tree + ML-DSA-65</div>
                </div>
                <div class="node-box">
                    <div class="node-title">Active Security Shield</div>
                    <div class="node-value" style="color: var(--neon-green);">RAG + ZK + PQC + eBPF</div>
                    <div style="font-size: 0.75rem; color: var(--neon-green); margin-top: 4px;">● CRDT Mesh Synchronized</div>
                </div>
            </div>
        </div>

        <!-- 14-Tactic MITRE ATT&CK Visual Navigator Matrix -->
        <div class="glass-card col-12">
            <div class="card-header">
                <h3>🎯 MITRE ATT&CK Matrix Heatmap (Enterprise & AI/LLM Tactics)</h3>
                <span class="mono" style="font-size: 0.78rem; color: var(--neon-cyan);">Live Coverage: 14/14 Tactics</span>
            </div>
            <div class="mitre-grid">
                <div class="mitre-cell active"><div class="mitre-cell-title">Initial Access</div><div class="mitre-cell-tech">T1190 Exploit Public App</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">Execution</div><div class="mitre-cell-tech">T1059 Command & Scripting</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Persistence</div><div class="mitre-cell-tech">T1543 Systemd Service</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">Privilege Esc</div><div class="mitre-cell-tech">T1068 Dirty Pipe Exploit</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">Defense Evasion</div><div class="mitre-cell-tech">T1027 Obfuscated Payloads</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Credential Access</div><div class="mitre-cell-tech">T1552 Unsecured Secrets</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Discovery</div><div class="mitre-cell-tech">T1082 System Info Discovery</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Lateral Movement</div><div class="mitre-cell-tech">T1021 Remote Services</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Collection</div><div class="mitre-cell-tech">T1005 Data from Local System</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">C2 Channel</div><div class="mitre-cell-tech">T1071 App Layer Protocol</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Exfiltration</div><div class="mitre-cell-tech">T1048 Exfiltration Over C2</div></div>
                <div class="mitre-cell"><div class="mitre-cell-title">Impact</div><div class="mitre-cell-tech">T1486 Data Encryption (Canary)</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">LLM Prompt Inject</div><div class="mitre-cell-tech">T1059.007 DAN & Jailbreak</div></div>
                <div class="mitre-cell active"><div class="mitre-cell-title">Supply Chain</div><div class="mitre-cell-tech">T1195 XZ Backdoor Liblzma</div></div>
            </div>
        </div>

        <!-- Live Attack Trajectory Graph -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🌐 Live Attack Trajectory Graph</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">Topology Map</span>
            </div>
            <canvas id="attack-canvas"></canvas>
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">
                <span>● Green: Core Engine</span>
                <span>● Yellow: Honeypot Traps</span>
                <span>● Red: Isolated Attackers</span>
            </div>
        </div>

        <!-- Realtime WebSocket Threat Waterfall Feed -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>📡 Live Threat Waterfall Feed (`/ws/telemetry`)</h3>
                <span class="mono" style="font-size: 0.78rem; color: var(--neon-green);" id="ws-status">● WebSocket Connected</span>
            </div>
            <div class="waterfall-feed" id="waterfall-container">
                <div class="feed-item low">
                    <div><strong>[SYSTEM_INIT]</strong> Jia Security Telemetry Engine initialized and listening.</div>
                    <span class="mono" style="font-size: 0.75rem; color: var(--text-muted);">now</span>
                </div>
            </div>
        </div>

        <!-- Merkle Tree WORM Inclusion Proof & PQC Validator -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🌳 Merkle Tree WORM Inclusion Proof</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-green);">NIST ML-DSA-65 Signed</span>
            </div>
            <input type="text" id="merkle-log-id" placeholder="Enter WORM Log ID for proof..." value="1">
            <button onclick="verifyMerkleProof()">Generate & Verify $O(\log N)$ Merkle Proof</button>
            <div style="margin-top: 14px;" class="output-box" id="merkle-output">Merkle proof path and quantum signature will appear here...</div>
        </div>

        <!-- STIX 2.1 / TAXII Threat Ingestor -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>📥 STIX 2.1 Threat Feed Ingestor</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">CISA & OTX Compliant</span>
            </div>
            <button onclick="ingestStixFeed()">Ingest CISA STIX 2.1 Threat Feed</button>
            <div style="margin-top: 14px;" class="output-box" id="stix-output">Click button to ingest STIX indicators into Vector RAG...</div>
        </div>

        <!-- Sigma-to-Rhai Detection Rule Studio -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>⚙️ Sigma-to-Rhai SOAR Transpiler Studio</h3>
            </div>
            <textarea id="sigma-input" rows="4">title: Suspicious Ptrace Memory Injection
detection:
    selection:
        CommandLine|contains: 'ptrace_inject'
    condition: selection</textarea>
            <button onclick="transpileSigmaRule()">Transpile to Rhai Playbook & YARA</button>
            <div style="margin-top: 14px;" class="output-box" id="sigma-output">Transpiled Rhai playbook will appear here...</div>
        </div>

        <!-- Kernel LSM eBPF Proactive Prevention -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🛡️ Kernel LSM eBPF Proactive Prevention</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">bpf_lsm_bprm Hook</span>
            </div>
            <input type="text" id="lsm-path" placeholder="Binary path (e.g. /tmp/memfd_create_payload)..." value="/tmp/memfd_create_payload">
            <button onclick="evaluateLsmHook()">Evaluate In-Kernel Pre-Exec Hook</button>
            <div style="margin-top: 14px;" class="output-box" id="lsm-output">In-kernel decision will appear here...</div>
        </div>

        <!-- Zero-Trust Microsegmentation -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🔀 Zero-Trust Network Microsegmentation</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">Dynamic Workload ACL</span>
            </div>
            <input type="text" id="microseg-src" placeholder="Source workload..." value="api-gateway">
            <button onclick="checkMicrosegFlow()">Check Workload Ingress Policy</button>
            <div style="margin-top: 14px;" class="output-box" id="microseg-output">Microsegmentation decision will appear here...</div>
        </div>

        <!-- Threshold Post-Quantum MPC Keys -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🔐 Threshold Post-Quantum MPC (t-of-n)</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-purple);">Shamir + ML-DSA-65</span>
            </div>
            <button onclick="runMpcThresholdSign()">Execute 3-of-5 MPC Quorum Signature</button>
            <div style="margin-top: 14px;" class="output-box" id="mpc-output">MPC quorum result will appear here...</div>
        </div>

        <!-- NIST SP 800-86 Forensic Evidence Bag -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>📦 Forensic Evidence Bag (NIST SP 800-86)</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-green);">Cryptographically Sealed</span>
            </div>
            <button onclick="exportForensicBag()">Export Forensically Sealed Bundle</button>
            <div style="margin-top: 14px;" class="output-box" id="evidence-output">Evidence bag checksums and PQC signatures will appear here...</div>
        </div>

        <!-- Kernel eBPF XDP Wire-Speed DDoS Dropper -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>⚡ Kernel eBPF XDP Wire-Speed DDoS Dropper</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-red);">14.8 Mpps FastPath</span>
            </div>
            <button onclick="simulateXdpSynFlood()">Simulate 120,000 pps SYN Flood</button>
            <div style="margin-top: 14px;" class="output-box" id="xdp-output">XDP driver-level packet drop telemetry will appear here...</div>
        </div>

        <!-- Post-Quantum ZK-Rollup Batch Ledger -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>📜 Post-Quantum ZK-Rollup Batch Ledger</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-purple);">Recursive ZK-SNARK + ML-DSA-65</span>
            </div>
            <button onclick="generateZkRollup()">Compress WORM Audit Batch into ZK Root</button>
            <div style="margin-top: 14px;" class="output-box" id="rollup-output">Rollup compression ratio and state root will appear here...</div>
        </div>

        <!-- TPM 2.0 Remote Enclave Attestation -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🛡️ TPM 2.0 Remote Enclave Attestation</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">AMD SEV-SNP / PCR Quotes</span>
            </div>
            <button onclick="verifyTpmAttestation()">Verify Node PCR Hardware Quotes</button>
            <div style="margin-top: 14px;" class="output-box" id="tpm-output">Hardware enclave quote & signature will appear here...</div>
        </div>

        <!-- Post-Quantum WireGuard Mesh VPN -->
        <div class="glass-card col-6">
            <div class="card-header">
                <h3>🌐 Post-Quantum WireGuard Mesh VPN</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-green);">ML-KEM-768 Ephemeral Rekeying</span>
            </div>
            <button onclick="fetchVpnMeshStatus()">Inspect Active VPN Overlay Mesh</button>
            <div style="margin-top: 14px;" class="output-box" id="vpn-output">Quantum-safe peer tunnels and byte counters will appear here...</div>
        </div>

        <!-- Natural Language SecOps Copilot -->
        <div class="glass-card col-12">
            <div class="card-header">
                <h3>🤖 Natural Language SecOps AI Copilot</h3>
                <span class="mono" style="font-size: 0.75rem; color: var(--neon-cyan);">Conversational IR Assistant</span>
            </div>
            <input type="text" id="copilot-input" placeholder="Ask Jia Copilot (e.g. 'Jia, quarantine attacker 198.51.100.42 immediately')..." value="Jia, quarantine attacker 198.51.100.42 immediately">
            <button onclick="querySecOpsCopilot()">Send Instruction to SecOps Copilot</button>
            <div style="margin-top: 14px;" class="output-box" id="copilot-output">Copilot reasoning and autonomous containment actions will appear here...</div>
        </div>
    </div>



    <script>
        // WebSocket Telemetry Feed
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/telemetry`;
        let ws;

        function initWebSocket() {
            ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                document.getElementById('ws-status').innerHTML = '● WebSocket Connected';
                document.getElementById('ws-status').style.color = '#00ff66';
            };
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    addWaterfallItem(data);
                } catch (e) {
                    console.error('WS parse error:', e);
                }
            };
            ws.onclose = () => {
                document.getElementById('ws-status').innerHTML = '○ Reconnecting...';
                document.getElementById('ws-status').style.color = '#f59e0b';
                setTimeout(initWebSocket, 2000);
            };
        }

        function addWaterfallItem(item) {
            const container = document.getElementById('waterfall-container');
            const el = document.createElement('div');
            let riskClass = 'low';
            if (item.risk_level.includes('CRITICAL')) riskClass = 'critical';
            else if (item.risk_level.includes('HIGH')) riskClass = 'high';

            el.className = `feed-item ${riskClass}`;
            el.innerHTML = `
                <div><strong>[${item.event_type}]</strong> ${item.source_ip} - ${item.details}</div>
                <span class="mono" style="font-size: 0.72rem; color: #94a3b8;">${new Date().toLocaleTimeString()}</span>
            `;
            container.insertBefore(el, container.firstChild);
            if (container.children.length > 30) {
                container.removeChild(container.lastChild);
            }
        }

        // Draw Canvas Attack Graph
        function drawAttackGraph() {
            const canvas = document.getElementById('attack-canvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            canvas.width = canvas.offsetWidth;
            canvas.height = canvas.offsetHeight;

            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Center Node: Jia Core
            const cx = canvas.width / 2;
            const cy = canvas.height / 2;

            ctx.fillStyle = '#00ff66';
            ctx.beginPath();
            ctx.arc(cx, cy, 14, 0, Math.PI * 2);
            ctx.fill();

            // Satellites
            const satellites = [
                { x: cx - 90, y: cy - 40, color: '#f59e0b', label: 'Honeypot /env' },
                { x: cx + 90, y: cy - 40, color: '#f59e0b', label: 'Honeypot /ssh' },
                { x: cx - 110, y: cy + 40, color: '#ff3366', label: 'Quarantined IP' },
                { x: cx + 110, y: cy + 40, color: '#00f0ff', label: 'BEAM Node' },
            ];

            satellites.forEach(s => {
                ctx.strokeStyle = 'rgba(0, 240, 255, 0.3)';
                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.lineTo(s.x, s.y);
                ctx.stroke();

                ctx.fillStyle = s.color;
                ctx.beginPath();
                ctx.arc(s.x, s.y, 8, 0, Math.PI * 2);
                ctx.fill();

                ctx.fillStyle = '#94a3b8';
                ctx.font = '10px JetBrains Mono';
                ctx.fillText(s.label, s.x - 30, s.y - 12);
            });
        }

        // API Action Functions
        async function verifyMerkleProof() {
            const logId = parseInt(document.getElementById('merkle-log-id').value) || 1;
            const resp = await fetch('/api/v1/worm/merkle_proof', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ log_id: logId })
            });
            const data = await resp.json();
            document.getElementById('merkle-output').textContent = JSON.stringify(data, null, 2);
        }

        async function ingestStixFeed() {
            const resp = await fetch('/api/v1/stix/ingest', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await resp.json();
            document.getElementById('stix-output').textContent = JSON.stringify(data, null, 2);
        }

        async function transpileSigmaRule() {
            const yaml = document.getElementById('sigma-input').value;
            const resp = await fetch('/api/v1/sigma/transpile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sigma_rule_yaml: yaml })
            });
            const data = await resp.json();
            document.getElementById('sigma-output').textContent = JSON.stringify(data, null, 2);
        }

        async function runPurpleTeamSim() {
            const resp = await fetch('/api/v1/red_team/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await resp.json();
            document.getElementById('purple-output').textContent = JSON.stringify(data, null, 2);
        }

        async function evaluateLsmHook() {
            const path = document.getElementById('lsm-path').value;
            const resp = await fetch('/api/v1/lsm/evaluate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ binary_path: path })
            });
            const data = await resp.json();
            document.getElementById('lsm-output').textContent = JSON.stringify(data, null, 2);
        }

        async function checkMicrosegFlow() {
            const src = document.getElementById('microseg-src').value;
            const resp = await fetch('/api/v1/microseg/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_workload: src,
                    source_ip: "10.0.1.5",
                    dest_ip: "10.0.2.20",
                    dest_port: 9090,
                    protocol: "TCP",
                    requested_alpn: "http/1.1"
                })
            });
            const data = await resp.json();
            document.getElementById('microseg-output').textContent = JSON.stringify(data, null, 2);
        }

        async function runMpcThresholdSign() {
            const shares = [
                { share_id: 1, node_identity: "node_1", share_hex: "0102030405060708", threshold: 3, total_shares: 5 },
                { share_id: 2, node_identity: "node_2", share_hex: "0203040506070809", threshold: 3, total_shares: 5 },
                { share_id: 3, node_identity: "node_3", share_hex: "030405060708090a", threshold: 3, total_shares: 5 }
            ];
            const resp = await fetch('/api/v1/mpc/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: "ENTERPRISE_WORM_SNAPSHOT_ROOT_COMMIT",
                    participating_shares: shares
                })
            });
            const data = await resp.json();
            document.getElementById('mpc-output').textContent = JSON.stringify(data, null, 2);
        }

        async function exportForensicBag() {
            const resp = await fetch('/api/v1/forensics/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    incident_id: "INC-2026-AUTONOMOUS-01",
                    target_adversary: "198.51.100.42"
                })
            });
            const data = await resp.json();
            document.getElementById('evidence-output').textContent = JSON.stringify(data, null, 2);
        }

        async function simulateXdpSynFlood() {
            const resp = await fetch('/api/v1/xdp/filter', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    packet: {
                        src_ip: "45.33.32.100",
                        dst_ip: "10.0.0.1",
                        src_port: 54321,
                        dst_port: 443,
                        protocol: "TCP",
                        is_syn: true,
                        pps_rate: 120000,
                        payload_size: 64
                    }
                })
            });
            const data = await resp.json();
            document.getElementById('xdp-output').textContent = JSON.stringify(data, null, 2);
        }

        async function generateZkRollup() {
            const resp = await fetch('/api/v1/zk/rollup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ batch_size: 100 })
            });
            const data = await resp.json();
            document.getElementById('rollup-output').textContent = JSON.stringify(data, null, 2);
        }

        async function verifyTpmAttestation() {
            const resp = await fetch('/api/v1/tpm/attest', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    node_id: "jia_node_1@beam_cluster",
                    nonce: "dashboard_nonce_" + Date.now()
                })
            });
            const data = await resp.json();
            document.getElementById('tpm-output').textContent = JSON.stringify(data, null, 2);
        }

        async function fetchVpnMeshStatus() {
            const resp = await fetch('/api/v1/vpn/status');
            const data = await resp.json();
            document.getElementById('vpn-output').textContent = JSON.stringify(data, null, 2);
        }

        async function querySecOpsCopilot() {
            const prompt = document.getElementById('copilot-input').value;
            const resp = await fetch('/api/v1/copilot/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: prompt })
            });
            const data = await resp.json();
            document.getElementById('copilot-output').textContent = JSON.stringify(data, null, 2);
        }



        // Poll health
        async function fetchHealth() {
            try {
                const resp = await fetch('/api/v1/health');
                const data = await resp.json();
                document.getElementById('uptime-display').textContent = `Uptime: ${data.uptime_seconds}s`;
                document.getElementById('worm-count-val').textContent = `${data.worm_audit_entries} Entries`;
            } catch (e) {}
        }

        window.onload = () => {
            initWebSocket();
            fetchHealth();
            setInterval(fetchHealth, 3000);
            drawAttackGraph();
            window.addEventListener('resize', drawAttackGraph);
        };
    </script>
</body>
</html>
"#;
    Html(html.to_string())
}
