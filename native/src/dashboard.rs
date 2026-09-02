use axum::response::Html;

pub fn render_dashboard() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jia Autonomous Cyber Command Center</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,600;0,700;1,400&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #070913;
            --bg-card: rgba(15, 23, 42, 0.75);
            --bg-card-hover: rgba(24, 34, 58, 0.88);
            --bg-input: rgba(6, 11, 22, 0.88);
            --border-glow: rgba(6, 182, 212, 0.25);
            --border-subtle: rgba(255, 255, 255, 0.08);
            
            --cyan: #06b6d4;
            --cyan-glow: rgba(6, 182, 212, 0.4);
            --emerald: #10b981;
            --emerald-glow: rgba(16, 185, 129, 0.4);
            --purple: #a855f7;
            --purple-glow: rgba(168, 85, 247, 0.4);
            --amber: #f59e0b;
            --crimson: #f43f5e;
            --crimson-glow: rgba(244, 63, 94, 0.4);

            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(ellipse 80% 80% at 50% -20%, rgba(6, 182, 212, 0.15), rgba(255, 255, 255, 0)),
                radial-gradient(ellipse 60% 60% at 100% 100%, rgba(168, 85, 247, 0.12), rgba(255, 255, 255, 0));
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            padding: 24px;
            overflow-x: hidden;
        }

        h1, h2, h3, h4, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Top Header Navbar */
        .top-navbar {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-glow);
            border-radius: 18px;
            padding: 16px 28px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 10px 40px 0 rgba(0, 0, 0, 0.5);
        }

        .brand-box {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-logo {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, var(--cyan), var(--purple));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            box-shadow: 0 0 20px var(--cyan-glow);
        }

        .brand-title h1 {
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #38bdf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-title p {
            color: var(--text-muted);
            font-size: 0.8rem;
            font-weight: 500;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .status-pill {
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.35);
            color: var(--emerald);
            padding: 8px 16px;
            border-radius: 30px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pulse-indicator {
            width: 8px;
            height: 8px;
            background-color: var(--emerald);
            border-radius: 50%;
            box-shadow: 0 0 12px var(--emerald);
            animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        @keyframes pulse-ring {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1.05); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .btn-purple-detonate {
            background: linear-gradient(135deg, rgba(244, 63, 94, 0.25), rgba(168, 85, 247, 0.25));
            border: 1px solid var(--crimson);
            color: #fff;
            padding: 9px 18px;
            border-radius: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.25s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-purple-detonate:hover {
            background: linear-gradient(135deg, rgba(244, 63, 94, 0.45), rgba(168, 85, 247, 0.45));
            box-shadow: 0 0 18px var(--crimson-glow);
            transform: translateY(-2px);
        }

        /* KPI Metric Hero Grid */
        .kpi-hero-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .kpi-card {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 18px 20px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .kpi-card:hover {
            border-color: var(--border-glow);
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
        }

        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--cyan);
        }

        .kpi-card.purple::before { background: var(--purple); }
        .kpi-card.emerald::before { background: var(--emerald); }
        .kpi-card.amber::before { background: var(--amber); }

        .kpi-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .kpi-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.4rem;
            font-weight: 700;
            margin-top: 6px;
            color: #fff;
        }

        .kpi-subtext {
            font-size: 0.75rem;
            color: var(--emerald);
            margin-top: 6px;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        /* Navigation Tab Bar */
        .tab-bar {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 12px;
        }

        .tab-btn {
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid var(--border-subtle);
            color: var(--text-muted);
            padding: 10px 20px;
            border-radius: 10px;
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab-btn:hover {
            color: #fff;
            background: rgba(30, 41, 59, 0.7);
            border-color: var(--border-glow);
        }

        .tab-btn.active {
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(168, 85, 247, 0.2));
            border-color: var(--cyan);
            color: #fff;
            box-shadow: 0 0 14px rgba(6, 182, 212, 0.25);
        }

        /* Main Dashboard Content Layout */
        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 20px;
        }

        .col-12 { grid-column: span 12; }
        .col-8 { grid-column: span 8; }
        .col-6 { grid-column: span 6; }
        .col-4 { grid-column: span 4; }

        /* Glass Cards */
        .card-panel {
            background: var(--bg-card);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 22px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.35);
        }

        .card-panel:hover {
            border-color: var(--border-glow);
            background: var(--bg-card-hover);
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }

        .panel-title {
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--cyan);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .panel-tag {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 6px;
            background: rgba(6, 182, 212, 0.12);
            color: var(--cyan);
            border: 1px solid rgba(6, 182, 212, 0.25);
        }

        /* Input & Controls */
        .form-group {
            margin-bottom: 12px;
        }

        .form-row {
            display: flex;
            gap: 10px;
        }

        label {
            display: block;
            font-size: 0.78rem;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 500;
        }

        input[type="text"], input[type="number"], textarea, select {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 10px;
            padding: 11px 14px;
            color: var(--text-main);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            outline: none;
            transition: all 0.2s ease;
        }

        input[type="text"]:focus, input[type="number"]:focus, textarea:focus, select:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 14px var(--cyan-glow);
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.82rem;
            color: var(--text-main);
            cursor: pointer;
        }

        .action-btn {
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(168, 85, 247, 0.2));
            border: 1px solid var(--cyan);
            color: #fff;
            padding: 10px 18px;
            border-radius: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            width: 100%;
            display: inline-flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            margin-top: 6px;
        }

        .action-btn:hover {
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.4), rgba(168, 85, 247, 0.4));
            box-shadow: 0 0 14px var(--cyan-glow);
            transform: translateY(-1px);
        }

        /* Terminal Console Boxes */
        .terminal-box {
            background: rgba(4, 7, 14, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            max-height: 220px;
            overflow-y: auto;
            color: var(--emerald);
            white-space: pre-wrap;
            margin-top: 14px;
            line-height: 1.5;
            box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.6);
        }

        /* Waterfall Telemetry Stream */
        .waterfall-container {
            max-height: 240px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .feed-card {
            background: rgba(10, 16, 28, 0.7);
            border-left: 4px solid var(--cyan);
            border-radius: 6px 10px 10px 6px;
            padding: 10px 14px;
            font-size: 0.82rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s ease;
        }

        .feed-card:hover {
            background: rgba(18, 28, 48, 0.85);
        }

        .feed-card.critical { border-left-color: var(--crimson); }
        .feed-card.high { border-left-color: var(--amber); }
        .feed-card.low { border-left-color: var(--emerald); }

        /* MITRE Heatmap Matrix Grid */
        .mitre-grid-wrapper {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 10px;
        }

        .mitre-tile {
            background: rgba(10, 16, 28, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 10px;
            transition: all 0.25s ease;
        }

        .mitre-tile.active {
            border-color: var(--crimson);
            background: rgba(244, 63, 94, 0.15);
            box-shadow: 0 0 12px rgba(244, 63, 94, 0.3);
        }

        .mitre-title {
            font-size: 0.78rem;
            font-weight: 700;
            color: var(--cyan);
            margin-bottom: 4px;
        }

        .mitre-code {
            color: var(--text-muted);
            font-size: 0.7rem;
            font-family: 'JetBrains Mono', monospace;
        }

        #attack-canvas {
            width: 100%;
            height: 220px;
            background: rgba(4, 7, 14, 0.85);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }

        @media (max-width: 1024px) {
            .kpi-hero-grid { grid-template-columns: repeat(2, 1fr); }
            .mitre-grid-wrapper { grid-template-columns: repeat(3, 1fr); }
            .col-6, .col-8, .col-4 { grid-column: span 12; }
        }
    </style>
</head>
<body>

    <!-- Header Navigation Bar -->
    <div class="top-navbar">
        <div class="brand-box">
            <div class="brand-logo">️</div>
            <div class="brand-title">
                <h1>JIA CYBER COMMAND CENTER</h1>
                <p>Erlang OTP Actor Cluster (Gleam) + Native SecOps Engine (Rust Vella)</p>
            </div>
        </div>

        <div class="header-actions">
            <button class="btn-purple-detonate" onclick="runPurpleTeamSim()">
                <span>⚔️</span> Run Purple Team Simulation
            </button>
            <div class="status-pill">
                <div class="pulse-indicator"></div>
                <span id="system-status-text">SYSTEM OPERATIONAL | BEAM OTP SUPERVISED</span>
            </div>
        </div>
    </div>

    <!-- Executive KPI Metric Bar -->
    <div class="kpi-hero-grid">
        <div class="kpi-card">
            <div class="kpi-label">Erlang BEAM Cluster</div>
            <div class="kpi-value" style="color: var(--cyan);">jia@beam-daemon</div>
            <div class="kpi-subtext">● OTP Supervision Tree Active</div>
        </div>
        <div class="kpi-card purple">
            <div class="kpi-label">Rust Native Sidecar</div>
            <div class="kpi-value" style="color: var(--purple);">http://127.0.0.1:9090</div>
            <div class="kpi-subtext" style="color: var(--purple);">● Axum + Vella High-Speed Engine</div>
        </div>
        <div class="kpi-card emerald">
            <div class="kpi-label">WORM Audit Ledger</div>
            <div class="kpi-value" id="worm-count-val" style="color: var(--emerald);">0 Entries</div>
            <div class="kpi-subtext">● Merkle Tree + NIST ML-DSA-65</div>
        </div>
        <div class="kpi-card amber">
            <div class="kpi-label">Active Defense Stack</div>
            <div class="kpi-value" style="color: var(--amber);">eBPF + PQC + RAG</div>
            <div class="kpi-subtext" id="uptime-display" style="color: var(--amber);">Uptime: 0s</div>
        </div>
    </div>

    <!-- Navigation Category Tabs -->
    <div class="tab-bar">
        <button class="tab-btn active" onclick="switchTab('tab-threat-ops')"> Threat Operations & Topology</button>
        <button class="tab-btn" onclick="switchTab('tab-kernel-defense')">⚡ Kernel & Microsegmentation</button>
        <button class="tab-btn" onclick="switchTab('tab-airgapped-ai')"> Air-Gapped Cognitive AI</button>
        <button class="tab-btn" onclick="switchTab('tab-pqc-ledger')"> Post-Quantum PQC & Ledgers</button>
        <button class="tab-btn" onclick="switchTab('tab-intel-rules')">🎯 Threat Intel & Rules Studio</button>
    </div>

    <!-- TAB 1: THREAT OPERATIONS & TOPOLOGY -->
    <div id="tab-threat-ops" class="tab-content active">
        <!-- Live WebSocket Threat Feed -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Live Threat Telemetry Waterfall (`/ws/telemetry`)</div>
                <div class="panel-tag" id="ws-status" style="color: var(--emerald);">● Connected</div>
            </div>
            <div class="waterfall-container" id="waterfall-container">
                <div class="feed-card low">
                    <div><strong>[SYSTEM_INIT]</strong> Jia Telemetry Engine initialized and monitoring cluster.</div>
                    <span class="mono" style="font-size: 0.72rem; color: var(--text-muted);">now</span>
                </div>
            </div>
        </div>

        <!-- Attack Trajectory Canvas Map -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Live Attack Trajectory Map</div>
                <div class="panel-tag">Topology Node Graph</div>
            </div>
            <canvas id="attack-canvas"></canvas>
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-top: 8px;">
                <span>● Green: Core Engine</span>
                <span>● Yellow: Honeypot Decoys</span>
                <span>● Red: Isolated Adversaries (Dynamic)</span>
            </div>
        </div>

        <!-- MITRE ATT&CK Matrix -->
        <div class="card-panel col-12">
            <div class="panel-header">
                <div class="panel-title"> MITRE ATT&CK Matrix Heatmap (Enterprise & AI/LLM Tactics)</div>
                <div class="panel-tag">14 Active Tactics Covered</div>
            </div>
            <div class="mitre-grid-wrapper">
                <div class="mitre-tile active"><div class="mitre-title">Initial Access</div><div class="mitre-code">T1190 Exploit Public App</div></div>
                <div class="mitre-tile active"><div class="mitre-title">Execution</div><div class="mitre-code">T1059 Command & Scripting</div></div>
                <div class="mitre-tile"><div class="mitre-title">Persistence</div><div class="mitre-code">T1543 Systemd Service</div></div>
                <div class="mitre-tile active"><div class="mitre-title">Privilege Esc</div><div class="mitre-code">T1068 Dirty Pipe Exploit</div></div>
                <div class="mitre-tile active"><div class="mitre-title">Defense Evasion</div><div class="mitre-code">T1027 Obfuscated Payloads</div></div>
                <div class="mitre-tile"><div class="mitre-title">Credential Access</div><div class="mitre-code">T1552 Unsecured Secrets</div></div>
                <div class="mitre-tile"><div class="mitre-title">Discovery</div><div class="mitre-code">T1082 System Info Discovery</div></div>
                <div class="mitre-tile"><div class="mitre-title">Lateral Movement</div><div class="mitre-code">T1021 Remote Services</div></div>
                <div class="mitre-tile"><div class="mitre-title">Collection</div><div class="mitre-code">T1005 Data Local System</div></div>
                <div class="mitre-tile active"><div class="mitre-title">C2 Channel</div><div class="mitre-code">T1071 App Layer Protocol</div></div>
                <div class="mitre-tile"><div class="mitre-title">Exfiltration</div><div class="mitre-code">T1048 Exfiltration Over C2</div></div>
                <div class="mitre-tile"><div class="mitre-title">Impact</div><div class="mitre-code">T1486 Data Encryption</div></div>
                <div class="mitre-tile active"><div class="mitre-title">LLM Prompt Inject</div><div class="mitre-code">T1059.007 DAN & Jailbreak</div></div>
                <div class="mitre-tile active"><div class="mitre-title">Supply Chain</div><div class="mitre-code">T1195 XZ Backdoor Liblzma</div></div>
            </div>
        </div>
    </div>

    <!-- TAB 2: KERNEL & MICROSEGMENTATION -->
    <div id="tab-kernel-defense" class="tab-content">
        <!-- Kernel eBPF XDP DDoS Dropper -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title">⚡ In-Kernel eBPF XDP Wire-Speed DDoS Dropper</div>
                <div class="panel-tag">NIC FastPath 90ns Drop</div>
            </div>
            <div class="form-row">
                <div class="form-group" style="flex: 2;">
                    <label>Adversary Source IP</label>
                    <input type="text" id="xdp-src-ip" value="45.33.32.100" placeholder="Source IP...">
                </div>
                <div class="form-group" style="flex: 1;">
                    <label>PPS Rate</label>
                    <input type="number" id="xdp-pps" value="120000" placeholder="pps...">
                </div>
            </div>
            <div class="form-row" style="align-items: center; margin-bottom: 10px;">
                <div style="flex: 1;">
                    <label>Protocol</label>
                    <select id="xdp-proto">
                        <option value="TCP" selected>TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                    </select>
                </div>
                <div style="flex: 1; padding-top: 18px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="xdp-syn" checked> SYN Flood Flag
                    </label>
                </div>
            </div>
            <button class="action-btn" onclick="simulateXdpSynFlood()">Evaluate Kernel eBPF XDP Filter</button>
            <div class="terminal-box" id="xdp-output">eBPF XDP packet drop verdict will appear here...</div>
        </div>

        <!-- Kernel LSM eBPF Proactive Prevention -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title">️ Kernel LSM eBPF Pre-Execution Block</div>
                <div class="panel-tag">bpf_lsm_bprm Hook</div>
            </div>
            <div class="form-group">
                <label>Target Executable Binary Path</label>
                <input type="text" id="lsm-path" value="/tmp/memfd_create_payload" placeholder="Target binary path...">
            </div>
            <button class="action-btn" onclick="evaluateLsmHook()">Evaluate In-Kernel Pre-Exec Block (-EPERM)</button>
            <div class="terminal-box" id="lsm-output">In-kernel decision will appear here...</div>
        </div>

        <!-- Zero-Trust Microsegmentation -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Zero-Trust Network Microsegmentation</div>
                <div class="panel-tag">Workload Ingress ACL</div>
            </div>
            <div class="form-row">
                <div style="flex: 1;">
                    <label>Source Workload</label>
                    <input type="text" id="microseg-src" value="api-gateway">
                </div>
                <div style="flex: 1;">
                    <label>Destination IP</label>
                    <input type="text" id="microseg-dst-ip" value="10.0.2.20">
                </div>
                <div style="flex: 1;">
                    <label>Port</label>
                    <input type="number" id="microseg-dst-port" value="9090">
                </div>
            </div>
            <button class="action-btn" onclick="checkMicrosegFlow()">Evaluate Microsegmentation Policy</button>
            <div class="terminal-box" id="microseg-output">Microsegmentation policy verdict will appear here...</div>
        </div>

        <!-- Purple Team Simulation Output Panel -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title">⚔️ Continuous Purple Team Detonation Results</div>
                <div class="panel-tag">Multi-Vector Detonation</div>
            </div>
            <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 12px;">Runs automated red-team vector pass (T1059, Rootkit PrivEsc, DAN Jailbreak, SQLi, Honeypot Traps).</p>
            <button class="action-btn" onclick="runPurpleTeamSim()">Run Full Purple Team Detonation Matrix</button>
            <div class="terminal-box" id="purple-output">Click button above to execute automated Red/Purple Team simulations...</div>
        </div>
    </div>

    <!-- TAB 3: AIR-GAPPED COGNITIVE AI -->
    <div id="tab-airgapped-ai" class="tab-content">
        <!-- Local Air-Gapped Ollama SLM -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Air-Gapped Ollama SLM & Safety Gate</div>
                <div class="panel-tag">VRAM Cap: &lt;1.5GB</div>
            </div>
            <div class="form-group">
                <label>Threat Incident Description</label>
                <input type="text" id="ollama-threat" value="Zero-Day Remote Code Execution via unauthenticated memory injection">
            </div>
            <div class="form-group">
                <label>Target Adversary IP</label>
                <input type="text" id="ollama-target-ip" value="198.51.100.99">
            </div>
            <div class="form-row">
                <button class="action-btn" onclick="fetchOllamaStatus()">Inspect Ollama Models</button>
                <button class="action-btn" onclick="generateSafePlaybook()">Synthesize Rhai Playbook</button>
            </div>
            <div class="terminal-box" id="ollama-output">Local LLM status and safety-validated Rhai playbooks will appear here...</div>
        </div>

        <!-- Natural Language SecOps Copilot -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Natural Language SecOps AI Copilot</div>
                <div class="panel-tag">Conversational Incident Response</div>
            </div>
            <div class="form-group">
                <label>Natural Language Instruction / Query</label>
                <input type="text" id="copilot-input" value="Jia, quarantine attacker 198.51.100.42 immediately" placeholder="Enter command to Jia Copilot...">
            </div>
            <button class="action-btn" onclick="querySecOpsCopilot()">Execute Copilot Instruction</button>
            <div class="terminal-box" id="copilot-output">SecOps Copilot reasoning and containment logs will appear here...</div>
        </div>
    </div>

    <!-- TAB 4: POST-QUANTUM CRYPTOGRAPHY & LEDGERS -->
    <div id="tab-pqc-ledger" class="tab-content">
        <!-- Merkle Tree WORM Proof -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Merkle Tree WORM Inclusion Proof</div>
                <div class="panel-tag">NIST ML-DSA-65 Signed</div>
            </div>
            <div class="form-group">
                <label>WORM Log Entry ID</label>
                <input type="number" id="merkle-log-id" value="1" placeholder="Enter log entry ID...">
            </div>
            <button class="action-btn" onclick="verifyMerkleProof()">Verify $O(\log N)$ Merkle Proof</button>
            <div class="terminal-box" id="merkle-output">Merkle proof path and ML-DSA signature will appear here...</div>
        </div>

        <!-- Post-Quantum ZK-Rollup -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Post-Quantum ZK-Rollup Batch Ledger</div>
                <div class="panel-tag">ZK-SNARK + ML-DSA-65</div>
            </div>
            <p style="font-size: 0.82rem; color: var(--text-muted); margin-bottom: 12px;">Compresses WORM audit logs into succinct state roots with quantum signatures.</p>
            <button class="action-btn" onclick="generateZkRollup()">Compress Audit Batch into ZK Root</button>
            <div class="terminal-box" id="rollup-output">ZK state root proof output will appear here...</div>
        </div>

        <!-- Threshold Post-Quantum MPC -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Threshold Post-Quantum MPC (t-of-n)</div>
                <div class="panel-tag">Shamir + ML-DSA-65</div>
            </div>
            <div class="form-group">
                <label>Message to Sign</label>
                <input type="text" id="mpc-msg" value="ENTERPRISE_WORM_SNAPSHOT_ROOT_COMMIT">
            </div>
            <button class="action-btn" onclick="runMpcThresholdSign()">Execute 3-of-5 MPC Quorum Signature</button>
            <div class="terminal-box" id="mpc-output">MPC quorum result will appear here...</div>
        </div>

        <!-- NIST SP 800-86 Evidence Bag -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Forensic Evidence Bag (NIST SP 800-86)</div>
                <div class="panel-tag">Cryptographically Sealed</div>
            </div>
            <div class="form-row">
                <div style="flex: 1;">
                    <label>Incident ID</label>
                    <input type="text" id="evidence-incident-id" value="INC-2026-AUTONOMOUS-01">
                </div>
                <div style="flex: 1;">
                    <label>Adversary Target</label>
                    <input type="text" id="evidence-target" value="198.51.100.42">
                </div>
            </div>
            <button class="action-btn" onclick="exportForensicBag()">Export Forensically Sealed Bundle</button>
            <div class="terminal-box" id="evidence-output">Evidence bag checksums and PQC signatures will appear here...</div>
        </div>

        <!-- TPM 2.0 Attestation -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title">️ TPM 2.0 Remote Enclave Attestation</div>
                <div class="panel-tag">AMD SEV-SNP / PCR Quotes</div>
            </div>
            <button class="action-btn" onclick="verifyTpmAttestation()">Verify Node PCR Hardware Quotes</button>
            <div class="terminal-box" id="tpm-output">TPM PCR quote signature will appear here...</div>
        </div>

        <!-- Post-Quantum WireGuard Mesh VPN -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> Post-Quantum WireGuard Mesh VPN</div>
                <div class="panel-tag">ML-KEM-768 Key Exchange</div>
            </div>
            <button class="action-btn" onclick="fetchVpnMeshStatus()">Inspect Active VPN Overlay Mesh</button>
            <div class="terminal-box" id="vpn-output">VPN quantum peer status will appear here...</div>
        </div>
    </div>

    <!-- TAB 5: THREAT INTEL & RULES STUDIO -->
    <div id="tab-intel-rules" class="tab-content">
        <!-- STIX 2.1 Threat Ingestor -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title"> STIX 2.1 / TAXII Threat Feed Ingestor</div>
                <div class="panel-tag">CISA & OTX Compliant</div>
            </div>
            <button class="action-btn" onclick="ingestStixFeed()">Ingest CISA STIX 2.1 Threat Feed</button>
            <div class="terminal-box" id="stix-output">STIX feed ingestion results will appear here...</div>
        </div>

        <!-- Sigma Rule Transpiler -->
        <div class="card-panel col-6">
            <div class="panel-header">
                <div class="panel-title">⚙️ Sigma-to-Rhai Detection Rule Studio</div>
                <div class="panel-tag">YAML to Rhai/YARA</div>
            </div>
            <div class="form-group">
                <label>Sigma YAML Detection Rule</label>
                <textarea id="sigma-input" rows="4">title: Suspicious Ptrace Memory Injection
detection:
    selection:
        CommandLine|contains: 'ptrace_inject'
    condition: selection</textarea>
            </div>
            <button class="action-btn" onclick="transpileSigmaRule()">Transpile to Rhai Playbook & YARA Rule</button>
            <div class="terminal-box" id="sigma-output">Transpiled output will appear here...</div>
        </div>
    </div>

    <script>
        let liveBlockedIps = ["198.51.100.42", "203.0.113.88"];

        // Tab Switcher
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            const selectedContent = document.getElementById(tabId);
            if (selectedContent) selectedContent.classList.add('active');
            
            const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
            if (activeBtn) activeBtn.classList.add('active');

            if (tabId === 'tab-threat-ops') {
                setTimeout(drawAttackGraph, 50);
            }
        }

        // WebSocket Telemetry Stream
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/telemetry`;
        let ws;

        function initWebSocket() {
            ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                document.getElementById('ws-status').innerHTML = '● Connected';
                document.getElementById('ws-status').style.color = 'var(--emerald)';
            };
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    addWaterfallItem(data);
                    if (data.action === 'QUARANTINE' || data.action === 'BLOCK') {
                        fetchHealth();
                    }
                } catch (e) {
                    console.error('WS parse error:', e);
                }
            };
            ws.onclose = () => {
                document.getElementById('ws-status').innerHTML = '○ Reconnecting...';
                document.getElementById('ws-status').style.color = 'var(--amber)';
                setTimeout(initWebSocket, 2000);
            };
        }

        function addWaterfallItem(item) {
            const container = document.getElementById('waterfall-container');
            const el = document.createElement('div');
            let riskClass = 'low';
            if (item.risk_level.includes('CRITICAL')) riskClass = 'critical';
            else if (item.risk_level.includes('HIGH')) riskClass = 'high';

            el.className = `feed-card ${riskClass}`;
            el.innerHTML = `
                <div><strong>[${item.event_type}]</strong> ${item.source_ip} - ${item.details}</div>
                <span class="mono" style="font-size: 0.72rem; color: var(--text-muted);">${new Date().toLocaleTimeString()}</span>
            `;
            container.insertBefore(el, container.firstChild);
            if (container.children.length > 30) {
                container.removeChild(container.lastChild);
            }
        }

        // Dynamic Canvas Attack Graph Renderer
        function drawAttackGraph() {
            const canvas = document.getElementById('attack-canvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            canvas.width = canvas.offsetWidth;
            canvas.height = canvas.offsetHeight;

            ctx.clearRect(0, 0, canvas.width, canvas.height);

            const cx = canvas.width / 2;
            const cy = canvas.height / 2;

            // Pulsing Center Core Node: Jia BEAM Core Engine
            ctx.shadowBlur = 16;
            ctx.shadowColor = 'rgba(16, 185, 129, 0.8)';
            ctx.fillStyle = '#10b981';
            ctx.beginPath();
            ctx.arc(cx, cy, 14, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.fillStyle = '#ffffff';
            ctx.font = '700 11px JetBrains Mono';
            ctx.fillText('JIA OTP CORE', cx - 36, cy + 28);

            // Dynamic Satellites: Real Honeypot Decoys & Real Quarantined Adversaries
            const staticDecoys = [
                { color: '#f59e0b', label: 'Honeypot /env' },
                { color: '#f59e0b', label: 'Honeypot /ssh' },
            ];

            let nodesToDraw = [];
            
            // Add honeypot decoys
            staticDecoys.forEach((dec, idx) => {
                const angle = (idx * Math.PI) - (Math.PI / 4);
                nodesToDraw.push({
                    x: cx + Math.cos(angle) * 110,
                    y: cy + Math.sin(angle) * 60,
                    color: dec.color,
                    label: dec.label
                });
            });

            // Add real blocked/quarantined IPs
            const blockedList = liveBlockedIps.length > 0 ? liveBlockedIps : ["198.51.100.42", "203.0.113.88"];
            blockedList.slice(0, 5).forEach((ip, idx) => {
                const angle = (idx + 2) * (Math.PI / 3);
                nodesToDraw.push({
                    x: cx + Math.cos(angle) * 130,
                    y: cy + Math.sin(angle) * 75,
                    color: '#f43f5e',
                    label: `Quarantined ${ip}`
                });
            });

            nodesToDraw.forEach(s => {
                ctx.strokeStyle = 'rgba(6, 182, 212, 0.3)';
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.moveTo(cx, cy);
                ctx.lineTo(s.x, s.y);
                ctx.stroke();

                ctx.shadowBlur = 10;
                ctx.shadowColor = s.color;
                ctx.fillStyle = s.color;
                ctx.beginPath();
                ctx.arc(s.x, s.y, 8, 0, Math.PI * 2);
                ctx.fill();
                ctx.shadowBlur = 0;

                ctx.fillStyle = '#94a3b8';
                ctx.font = '10px JetBrains Mono';
                ctx.fillText(s.label, s.x - 35, s.y - 12);
            });
        }

        // Real API Action Functions
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
            const targetEl = document.getElementById('purple-output');
            if (targetEl) targetEl.textContent = JSON.stringify(data, null, 2);
            fetchHealth();
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
            const dstIp = document.getElementById('microseg-dst-ip').value;
            const dstPort = parseInt(document.getElementById('microseg-dst-port').value) || 9090;

            const resp = await fetch('/api/v1/microseg/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_workload: src,
                    source_ip: "10.0.1.5",
                    dest_ip: dstIp,
                    dest_port: dstPort,
                    protocol: "TCP",
                    requested_alpn: "http/1.1"
                })
            });
            const data = await resp.json();
            document.getElementById('microseg-output').textContent = JSON.stringify(data, null, 2);
        }

        async function runMpcThresholdSign() {
            const msg = document.getElementById('mpc-msg').value;
            const shares = [
                { share_id: 1, node_identity: "node_1", share_hex: "0102030405060708", threshold: 3, total_shares: 5 },
                { share_id: 2, node_identity: "node_2", share_hex: "0203040506070809", threshold: 3, total_shares: 5 },
                { share_id: 3, node_identity: "node_3", share_hex: "030405060708090a", threshold: 3, total_shares: 5 }
            ];
            const resp = await fetch('/api/v1/mpc/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: msg,
                    participating_shares: shares
                })
            });
            const data = await resp.json();
            document.getElementById('mpc-output').textContent = JSON.stringify(data, null, 2);
        }

        async function exportForensicBag() {
            const incidentId = document.getElementById('evidence-incident-id').value;
            const target = document.getElementById('evidence-target').value;

            const resp = await fetch('/api/v1/forensics/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    incident_id: incidentId,
                    target_adversary: target
                })
            });
            const data = await resp.json();
            document.getElementById('evidence-output').textContent = JSON.stringify(data, null, 2);
        }

        async function simulateXdpSynFlood() {
            const srcIp = document.getElementById('xdp-src-ip').value;
            const ppsRate = parseInt(document.getElementById('xdp-pps').value) || 120000;
            const proto = document.getElementById('xdp-proto').value;
            const isSyn = document.getElementById('xdp-syn').checked;

            const resp = await fetch('/api/v1/xdp/filter', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    packet: {
                        src_ip: srcIp,
                        dst_ip: "10.0.0.1",
                        src_port: 54321,
                        dst_port: 443,
                        protocol: proto,
                        is_syn: isSyn,
                        pps_rate: ppsRate,
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

        async function fetchOllamaStatus() {
            const resp = await fetch('/api/v1/ollama/status');
            const data = await resp.json();
            document.getElementById('ollama-output').textContent = JSON.stringify(data, null, 2);
        }

        async function generateSafePlaybook() {
            const threat = document.getElementById('ollama-threat').value;
            const ip = document.getElementById('ollama-target-ip').value;
            const resp = await fetch('/api/v1/ollama/generate_playbook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    threat_description: threat,
                    target_ip: ip,
                    cve_id: "CVE-2026-ZERO-DAY"
                })
            });
            const data = await resp.json();
            document.getElementById('ollama-output').textContent = JSON.stringify(data, null, 2);
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
            fetchHealth();
        }

        // Real Dynamic Health & CRDT Mesh Sync Polling
        async function fetchHealth() {
            try {
                const resp = await fetch('/api/v1/health');
                const data = await resp.json();
                document.getElementById('uptime-display').textContent = `Uptime: ${data.uptime_seconds}s`;
                const wormCount = data.worm_log_count !== undefined ? data.worm_log_count : (data.worm_audit_entries || 0);
                document.getElementById('worm-count-val').textContent = `${wormCount} Entries`;

                // Fetch real distributed blocked IPs from CRDT Mesh Sync endpoint
                const meshResp = await fetch('/api/v1/mesh/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
                const meshData = await meshResp.json();
                if (meshData && meshData.blocked_ips) {
                    liveBlockedIps = meshData.blocked_ips;
                    drawAttackGraph();
                }
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
