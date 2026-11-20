"""
GameCleaner Web Dashboard Templates and Visual Assets.
Delivers a zero-dependency, self-contained, cyberpunk/military-grade cybersecurity dashboard.
"""

from typing import Any, Dict, Optional


def get_dashboard_html(csrf_token: str, server_info: Optional[Dict[str, Any]] = None) -> str:
    """Returns the complete, self-contained HTML5 single-page application dashboard."""
    server_info = server_info or {}
    host = server_info.get("host", "127.0.0.1")
    port = server_info.get("port", 8443)
    version = server_info.get("version", "1.0.0")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="{csrf_token}">
  <title>GameCleaner // Autonomous Cyber Defense Console</title>
  <style>
    :root {{
      --bg-dark: #080c14;
      --bg-card: rgba(14, 21, 37, 0.88);
      --bg-card-hover: rgba(20, 31, 54, 0.95);
      --border-cyan: rgba(0, 240, 255, 0.25);
      --border-glow: rgba(0, 240, 255, 0.5);
      --neon-cyan: #00f0ff;
      --neon-green: #00ff88;
      --neon-amber: #ffaa00;
      --neon-red: #ff3366;
      --neon-purple: #9d4edd;
      --text-main: #e2e8f0;
      --text-muted: #8b9bb4;
      --font-mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
      --font-sans: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(0, 240, 255, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 90% 80%, rgba(0, 255, 136, 0.03) 0%, transparent 40%),
        linear-gradient(rgba(8, 12, 20, 0.96), rgba(8, 12, 20, 0.96));
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }}

    /* Cyber Scanline Overlay */
    body::before {{
      content: "";
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.01), rgba(0, 255, 0, 0.005), rgba(0, 0, 255, 0.01));
      background-size: 100% 3px, 3px 100%;
      pointer-events: none;
      z-index: 9999;
    }}

    header {{
      background: rgba(10, 16, 28, 0.95);
      border-bottom: 1px solid var(--border-cyan);
      backdrop-filter: blur(12px);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 1000;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }}

    .logo-container {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}

    .hex-badge {{
      width: 42px;
      height: 42px;
      background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(0, 255, 136, 0.2));
      border: 1px solid var(--neon-cyan);
      clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-weight: 900;
      color: var(--neon-cyan);
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
    }}

    .logo-title h1 {{
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 2px;
      color: #ffffff;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .logo-title h1 span {{
      color: var(--neon-cyan);
      text-shadow: 0 0 10px rgba(0, 240, 255, 0.5);
    }}

    .logo-title p {{
      font-size: 11px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      letter-spacing: 1px;
    }}

    .header-badges {{
      display: flex;
      gap: 12px;
      align-items: center;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 12px;
      border-radius: 4px;
      font-size: 11px;
      font-family: var(--font-mono);
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }}

    .badge-cyan {{
      background: rgba(0, 240, 255, 0.1);
      border: 1px solid rgba(0, 240, 255, 0.4);
      color: var(--neon-cyan);
    }}

    .badge-green {{
      background: rgba(0, 255, 136, 0.1);
      border: 1px solid rgba(0, 255, 136, 0.4);
      color: var(--neon-green);
    }}

    .badge-amber {{
      background: rgba(255, 170, 0, 0.1);
      border: 1px solid rgba(255, 170, 0, 0.4);
      color: var(--neon-amber);
    }}

    .badge-red {{
      background: rgba(255, 51, 102, 0.1);
      border: 1px solid rgba(255, 51, 102, 0.4);
      color: var(--neon-red);
    }}

    .pulse-dot {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 8px currentColor;
      animation: pulse 1.8s infinite;
    }}

    @keyframes pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.4; transform: scale(0.85); }}
    }}

    /* Navigation Bar */
    nav {{
      background: rgba(12, 18, 32, 0.9);
      border-bottom: 1px solid rgba(0, 240, 255, 0.15);
      display: flex;
      padding: 0 32px;
      gap: 4px;
      overflow-x: auto;
    }}

    .nav-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      padding: 14px 20px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      position: relative;
      transition: all 0.2s ease;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}

    .nav-btn:hover {{
      color: #ffffff;
      background: rgba(0, 240, 255, 0.05);
    }}

    .nav-btn.active {{
      color: var(--neon-cyan);
      background: rgba(0, 240, 255, 0.08);
    }}

    .nav-btn.active::after {{
      content: "";
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: var(--neon-cyan);
      box-shadow: 0 0 10px var(--neon-cyan);
    }}

    /* Main Container */
    main {{
      flex: 1;
      padding: 32px;
      max-width: 1440px;
      margin: 0 auto;
      width: 100%;
    }}

    .tab-panel {{
      display: none;
      animation: fadeIn 0.25s ease-out;
    }}

    .tab-panel.active {{
      display: block;
    }}

    @keyframes fadeIn {{
      from {{ opacity: 0; transform: translateY(6px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}

    /* Card Panels */
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border-cyan);
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
      position: relative;
      margin-bottom: 24px;
      backdrop-filter: blur(8px);
    }}

    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }}

    .card-title {{
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .card-title-icon {{
      color: var(--neon-cyan);
    }}

    /* Grid Layouts */
    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 24px;
    }}

    .grid-3 {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 24px;
    }}

    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
    }}

    @media (max-width: 1024px) {{
      .grid-2, .grid-3, .grid-4 {{
        grid-template-columns: 1fr;
      }}
    }}

    /* Metric & Dial Cards */
    .metric-card {{
      background: rgba(11, 17, 31, 0.85);
      border: 1px solid rgba(0, 240, 255, 0.2);
      border-radius: 6px;
      padding: 20px;
      display: flex;
      align-items: center;
      gap: 20px;
      position: relative;
      overflow: hidden;
    }}

    .metric-card::before {{
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 3px;
      background: var(--neon-cyan);
      box-shadow: 0 0 10px var(--neon-cyan);
    }}

    .metric-dial {{
      position: relative;
      width: 72px;
      height: 72px;
      display: flex;
      align-items: center;
      justify-content: center;
    }}

    .dial-svg {{
      transform: rotate(-90deg);
      width: 72px;
      height: 72px;
    }}

    .dial-circle-bg {{
      fill: none;
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 6;
    }}

    .dial-circle-bar {{
      fill: none;
      stroke: var(--neon-cyan);
      stroke-width: 6;
      stroke-linecap: round;
      stroke-dasharray: 188;
      stroke-dashoffset: 47;
      transition: stroke-dashoffset 0.6s ease;
    }}

    .dial-value {{
      position: absolute;
      font-family: var(--font-mono);
      font-size: 15px;
      font-weight: 700;
      color: #ffffff;
    }}

    .metric-info h3 {{
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 6px;
    }}

    .metric-info .metric-num {{
      font-size: 26px;
      font-weight: 800;
      color: #ffffff;
      font-family: var(--font-mono);
    }}

    .metric-info .metric-sub {{
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
    }}

    /* Inputs & Form Elements */
    .input-group {{
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }}

    .text-input {{
      flex: 1;
      background: rgba(8, 13, 24, 0.9);
      border: 1px solid rgba(0, 240, 255, 0.3);
      border-radius: 4px;
      padding: 12px 16px;
      color: #ffffff;
      font-family: var(--font-mono);
      font-size: 13px;
      outline: none;
      transition: all 0.2s;
    }}

    .text-input:focus {{
      border-color: var(--neon-cyan);
      box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
    }}

    .btn {{
      background: rgba(0, 240, 255, 0.12);
      border: 1px solid var(--neon-cyan);
      color: var(--neon-cyan);
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      padding: 12px 24px;
      border-radius: 4px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s ease;
    }}

    .btn:hover {{
      background: var(--neon-cyan);
      color: #080c14;
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.5);
    }}

    .btn-green {{
      background: rgba(0, 255, 136, 0.12);
      border-color: var(--neon-green);
      color: var(--neon-green);
    }}

    .btn-green:hover {{
      background: var(--neon-green);
      color: #080c14;
      box-shadow: 0 0 16px rgba(0, 255, 136, 0.5);
    }}

    .btn-amber {{
      background: rgba(255, 170, 0, 0.12);
      border-color: var(--neon-amber);
      color: var(--neon-amber);
    }}

    .btn-amber:hover {{
      background: var(--neon-amber);
      color: #080c14;
      box-shadow: 0 0 16px rgba(255, 170, 0, 0.5);
    }}

    .btn-red {{
      background: rgba(255, 51, 102, 0.12);
      border-color: var(--neon-red);
      color: var(--neon-red);
    }}

    .btn-red:hover {{
      background: var(--neon-red);
      color: #080c14;
      box-shadow: 0 0 16px rgba(255, 51, 102, 0.5);
    }}

    .btn:disabled {{
      opacity: 0.5;
      cursor: not-allowed;
      box-shadow: none !important;
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.2);
      color: var(--text-muted);
    }}

    /* Tables */
    .table-container {{
      overflow-x: auto;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 4px;
      background: rgba(8, 12, 22, 0.6);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }}

    th {{
      background: rgba(14, 22, 38, 0.9);
      padding: 12px 16px;
      font-family: var(--font-mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      border-bottom: 1px solid rgba(0, 240, 255, 0.2);
    }}

    td {{
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text-main);
    }}

    tr:hover td {{
      background: rgba(0, 240, 255, 0.03);
    }}

    .mono {{
      font-family: var(--font-mono);
    }}

    /* Action Cards */
    .action-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
    }}

    .action-card {{
      background: rgba(11, 18, 33, 0.9);
      border: 1px solid rgba(0, 240, 255, 0.2);
      border-radius: 6px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.2s ease;
    }}

    .action-card:hover {{
      border-color: var(--neon-cyan);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 240, 255, 0.15);
    }}

    .action-card-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }}

    .action-icon {{
      width: 36px;
      height: 36px;
      background: rgba(0, 240, 255, 0.1);
      border: 1px solid rgba(0, 240, 255, 0.3);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--neon-cyan);
      font-size: 16px;
    }}

    .action-title {{
      font-size: 14px;
      font-weight: 700;
      color: #ffffff;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .action-desc {{
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 18px;
    }}

    /* Terminal Console */
    .terminal-box {{
      background: #05080f;
      border: 1px solid rgba(0, 240, 255, 0.2);
      border-radius: 4px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #a0aec0;
      height: 240px;
      overflow-y: auto;
      white-space: pre-wrap;
      line-height: 1.6;
    }}

    .terminal-box .term-green {{ color: var(--neon-green); }}
    .terminal-box .term-cyan {{ color: var(--neon-cyan); }}
    .terminal-box .term-amber {{ color: var(--neon-amber); }}
    .terminal-box .term-red {{ color: var(--neon-red); }}

    /* Toast Notifications */
    .toast-container {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 10000;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}

    .toast {{
      background: rgba(10, 16, 28, 0.95);
      border: 1px solid var(--neon-cyan);
      border-left-width: 4px;
      padding: 14px 20px;
      border-radius: 4px;
      color: #ffffff;
      font-family: var(--font-sans);
      font-size: 13px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 280px;
      animation: slideIn 0.3s ease-out;
    }}

    .toast-success {{ border-color: var(--neon-green); }}
    .toast-warning {{ border-color: var(--neon-amber); }}
    .toast-error {{ border-color: var(--neon-red); }}

    @keyframes slideIn {{
      from {{ opacity: 0; transform: translateX(40px); }}
      to {{ opacity: 1; transform: translateX(0); }}
    }}

    /* Progress bar */
    .progress-bar {{
      width: 100%;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      position: relative;
      overflow: hidden;
      border-radius: 2px;
      margin: 12px 0;
      display: none;
    }}

    .progress-bar.active {{
      display: block;
    }}

    .progress-bar::after {{
      content: "";
      position: absolute;
      left: -50%;
      top: 0;
      bottom: 0;
      width: 50%;
      background: linear-gradient(90deg, transparent, var(--neon-cyan), transparent);
      animation: sweep 1.5s infinite linear;
    }}

    @keyframes sweep {{
      0% {{ left: -50%; }}
      100% {{ left: 100%; }}
    }}
  </style>
</head>
<body>

  <!-- Header -->
  <header>
    <div class="logo-container">
      <div class="hex-badge">GC</div>
      <div class="logo-title">
        <h1>GAME<span>CLEANER</span> <small style="font-size: 11px; color: var(--neon-cyan);">v{version}</small></h1>
        <p>ZERO-DEPENDENCY LOCAL CYBERSECURITY COMMAND MATRIX</p>
      </div>
    </div>
    <div class="header-badges">
      <div class="badge badge-cyan" id="badge-host"><span class="pulse-dot"></span> BIND: {host}:{port}</div>
      <div class="badge badge-green" id="badge-admin">HOST INTEGRITY: ONLINE</div>
      <div class="badge badge-purple" id="badge-goldberg">GOLDBERG: READY</div>
    </div>
  </header>

  <!-- Navigation -->
  <nav>
    <button class="nav-btn active" onclick="switchTab('dashboard')">[01 // TELEMETRY]</button>
    <button class="nav-btn" onclick="switchTab('scanner')">[02 // TRIAGE & SCANNER]</button>
    <button class="nav-btn" onclick="switchTab('actions')">[03 // ONE-CLICK ACTIONS]</button>
    <button class="nav-btn" onclick="switchTab('vault')">[04 // SAVE VAULT]</button>
    <button class="nav-btn" onclick="switchTab('network')">[05 // NETWORK RADAR]</button>
  </nav>

  <!-- Main Content -->
  <main>

    <!-- TAB 1: DASHBOARD HOME -->
    <div id="tab-dashboard" class="tab-panel active">
      <!-- Metric Dials -->
      <div class="grid-4" style="margin-bottom: 24px;">
        <div class="metric-card">
          <div class="metric-dial">
            <svg class="dial-svg">
              <circle class="dial-circle-bg" cx="36" cy="36" r="30" />
              <circle class="dial-circle-bar" id="score-dial" cx="36" cy="36" r="30" style="stroke: var(--neon-green);" />
            </svg>
            <div class="dial-value" id="defense-score">98%</div>
          </div>
          <div class="metric-info">
            <h3>Defense Posture</h3>
            <div class="metric-num" id="posture-status">SECURE</div>
            <div class="metric-sub">Local Enclave Shield Active</div>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-dial">
            <svg class="dial-svg">
              <circle class="dial-circle-bg" cx="36" cy="36" r="30" />
              <circle class="dial-circle-bar" id="clean-dial" cx="36" cy="36" r="30" style="stroke: var(--neon-cyan); stroke-dashoffset: 40;" />
            </svg>
            <div class="dial-value" id="stat-clean">0</div>
          </div>
          <div class="metric-info">
            <h3>Clean Binaries</h3>
            <div class="metric-num" id="stat-clean-num">0</div>
            <div class="metric-sub">Verified & Sanitized</div>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-dial">
            <svg class="dial-svg">
              <circle class="dial-circle-bg" cx="36" cy="36" r="30" />
              <circle class="dial-circle-bar" id="warn-dial" cx="36" cy="36" r="30" style="stroke: var(--neon-amber); stroke-dashoffset: 150;" />
            </svg>
            <div class="dial-value" id="stat-warn">0</div>
          </div>
          <div class="metric-info">
            <h3>Suspicious / DRM</h3>
            <div class="metric-num" id="stat-warn-num">0</div>
            <div class="metric-sub">Sideloads & Hooks</div>
          </div>
        </div>

        <div class="metric-card">
          <div class="metric-dial">
            <svg class="dial-svg">
              <circle class="dial-circle-bg" cx="36" cy="36" r="30" />
              <circle class="dial-circle-bar" id="crit-dial" cx="36" cy="36" r="30" style="stroke: var(--neon-red); stroke-dashoffset: 188;" />
            </svg>
            <div class="dial-value" id="stat-crit">0</div>
          </div>
          <div class="metric-info">
            <h3>Quarantine Vault</h3>
            <div class="metric-num" id="stat-quar-num">0</div>
            <div class="metric-sub">Malware Payloads Isolated</div>
          </div>
        </div>
      </div>

      <!-- Quick Triage Launcher -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">&#9658;</span> Quick Game Triage & Target Selector</div>
          <span class="badge badge-cyan">AIR-GAPPED ENGINE</span>
        </div>
        <div class="input-group">
          <input type="text" id="quick-target-path" class="text-input" placeholder="Enter game folder path (e.g. D:\Games\SniperElite or C:\Downloads\repack.zip)..." />
          <button class="btn" onclick="startQuickScan()">TRIAGE SCAN</button>
          <button class="btn btn-green" onclick="startQuickClean()">CLEAN ALL</button>
        </div>
        <div id="quick-progress" class="progress-bar"></div>
      </div>

      <!-- System Diagnostics & Environment Matrix -->
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <div class="card-title"><span class="card-title-icon">&#9881;</span> Toolchain & Dependencies</div>
            <button class="btn" style="padding: 4px 12px; font-size: 11px;" onclick="fetchStatus()">REFRESH</button>
          </div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="toolchain-table">
                <tr><td>Goldberg Steam Emulator</td><td><span class="badge badge-green">VERIFIED</span></td><td>Pre-bundled x86 & x64 DLLs ready</td></tr>
                <tr><td>Innoextract Unpacker</td><td id="status-inno"><span class="badge badge-cyan">DETECTING...</span></td><td id="desc-inno">Scanning path</td></tr>
                <tr><td>Steamless CLI</td><td id="status-steamless"><span class="badge badge-cyan">DETECTING...</span></td><td id="desc-steamless">Scanning path</td></tr>
                <tr><td>Windows Sandbox Hypervisor</td><td id="status-sandbox"><span class="badge badge-cyan">DETECTING...</span></td><td id="desc-sandbox">Checking host capabilities</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title"><span class="card-title-icon">&#9733;</span> Active Defense Matrix</div>
            <span class="badge badge-green">LOCAL 127.0.0.1</span>
          </div>
          <div style="font-size: 13px; line-height: 1.8; color: var(--text-muted);">
            <p><strong style="color: #fff;">Autonomous Multi-Layer Containment:</strong></p>
            <ul style="padding-left: 20px; margin-top: 8px;">
              <li><strong style="color: var(--neon-cyan);">Emulator Swapping:</strong> Replaces hostile DRM/crack DLLs with clean Goldberg emulator without rebooting.</li>
              <li><strong style="color: var(--neon-green);">Save Game Preservation:</strong> Auto-migrates scene progress and preserves AppID identity.</li>
              <li><strong style="color: var(--neon-amber);">Process Shielding:</strong> Enforces DisallowChildProcessCreation against crypto-miners and droppers.</li>
              <li><strong style="color: var(--neon-red);">Firewall Isolation:</strong> Neutralizes outbound C2 telemetry traps via zero-click rules.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: SCANNER & TRIAGE -->
    <div id="tab-scanner" class="tab-panel">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">&#9635;</span> Game Directory / Archive Triage</div>
          <span class="badge badge-cyan">PARALLEL MULTI-CORE PE SCANNER</span>
        </div>
        <div class="input-group">
          <input type="text" id="scan-target-path" class="text-input" placeholder="Full path to game folder or repack installer..." />
          <button class="btn" id="btn-scan" onclick="runScan()">SCAN TARGET</button>
          <button class="btn btn-green" id="btn-clean" onclick="runClean()">RUN FULL PIPELINE</button>
        </div>
        <div id="scan-progress" class="progress-bar"></div>

        <!-- Threat Breakdown Badges -->
        <div style="display: flex; gap: 16px; margin: 16px 0;">
          <div class="badge badge-cyan" id="badge-total-files">TOTAL FILES: 0</div>
          <div class="badge badge-green" id="badge-clean-files">CLEAN: 0</div>
          <div class="badge badge-amber" id="badge-suspicious-files">SUSPICIOUS / DRM: 0</div>
          <div class="badge badge-red" id="badge-critical-files">CRITICAL MALWARE: 0</div>
        </div>

        <!-- Triage Results Table -->
        <div class="card-title" style="margin: 20px 0 10px 0; font-size: 13px;">Scanned Executables & Scripts Matrix</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>File Name</th>
                <th>Type</th>
                <th>Threat Score</th>
                <th>Severity</th>
                <th>Verdict / Findings</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="scan-results-tbody">
              <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 32px;">No scan performed yet. Enter a target directory above to begin triage.</td></tr>
            </tbody>
          </table>
        </div>

        <!-- Sideloaded DLLs Table -->
        <div class="card-title" style="margin: 28px 0 10px 0; font-size: 13px;"><span class="card-title-icon">&#9888;</span> Sideloaded DLLs & Search-Order Hijacking Audit</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>DLL Name</th>
                <th>Classification</th>
                <th>Severity</th>
                <th>Target Executable</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody id="sideload-results-tbody">
              <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No sideloaded DLLs detected.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: ONE-CLICK ACTIONS -->
    <div id="tab-actions" class="tab-panel">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">&#9889;</span> Autonomous Containment & Remediation Hub</div>
          <span class="badge badge-cyan">ZERO-CONFIG PRESETS</span>
        </div>
        <div class="input-group">
          <input type="text" id="action-target-path" class="text-input" placeholder="Select target game directory for action execution..." />
        </div>

        <div class="action-grid">
          <div class="action-card">
            <div>
              <div class="action-card-header">
                <div class="action-icon">&#9850;</div>
                <div class="action-title">Clean Emulator Replacement</div>
              </div>
              <div class="action-desc">Safely swaps closed-source crack DLLs with verified Goldberg emulator, creates steam_settings, and queries DLC store manifest.</div>
            </div>
            <button class="btn btn-green" onclick="executeAction('replace_emulator')">REPLACE EMULATOR</button>
          </div>

          <div class="action-card">
            <div>
              <div class="action-card-header">
                <div class="action-icon">&#9743;</div>
                <div class="action-title">Process Exploit Shield</div>
              </div>
              <div class="action-desc">Configures Windows Exploit Protection to block game binaries from spawning hidden cmd/powershell miners or droppers.</div>
            </div>
            <button class="btn btn-amber" onclick="executeAction('shield')">APPLY PROCESS SHIELD</button>
          </div>

          <div class="action-card">
            <div>
              <div class="action-card-header">
                <div class="action-icon">&#9964;</div>
                <div class="action-title">Firewall Isolation Scripts</div>
              </div>
              <div class="action-desc">Generates outbound blocking PowerShell scripts and Fix_Firewall_And_Run.bat launcher for private network LAN play.</div>
            </div>
            <button class="btn" onclick="executeAction('firewall')">GENERATE FIREWALL RULES</button>
          </div>

          <div class="action-card">
            <div>
              <div class="action-card-header">
                <div class="action-icon">&#9634;</div>
                <div class="action-title">Windows Sandbox Enclave</div>
              </div>
              <div class="action-desc">Generates an air-gapped, GPU-accelerated disposable Windows Sandbox (.wsb) execution profile.</div>
            </div>
            <button class="btn" onclick="executeAction('sandbox')">CREATE WSB SANDBOX</button>
          </div>

          <div class="action-card">
            <div>
              <div class="action-card-header">
                <div class="action-icon">&#128190;</div>
                <div class="action-title">Save Game Snapshot</div>
              </div>
              <div class="action-desc">Captures an instant, versioned zip snapshot of Goldberg emulator save files to prevent game progress loss.</div>
            </div>
            <button class="btn btn-cyan" onclick="executeAction('snapshot')">TAKE SAVE SNAPSHOT</button>
          </div>
        </div>

        <!-- Terminal Execution Log -->
        <div class="card-title" style="margin: 28px 0 10px 0; font-size: 13px;"><span class="card-title-icon">&#9656;</span> Execution Console Output</div>
        <div id="terminal-console" class="terminal-box">GameCleaner Cyber Defense Console ready. Select an action above to execute.</div>
      </div>
    </div>

    <!-- TAB 4: SAVE GAME VAULT -->
    <div id="tab-vault" class="tab-panel">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">&#128190;</span> Goldberg Save State Vault & Rollback Manager</div>
          <button class="btn btn-green" onclick="openSnapshotPrompt()">+ NEW SNAPSHOT</button>
        </div>
        <div class="input-group">
          <input type="text" id="vault-target-path" class="text-input" placeholder="Enter game folder path to inspect saves..." />
          <button class="btn" onclick="fetchSnapshots()">LIST SNAPSHOTS</button>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Snapshot Archive</th>
                <th>Steam AppID</th>
                <th>Timestamp</th>
                <th>Files</th>
                <th>Size</th>
                <th>Note / Label</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="snapshots-tbody">
              <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">No save snapshots loaded. Specify game path above.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 5: NETWORK RADAR -->
    <div id="tab-network" class="tab-panel">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="card-title-icon">&#9678;</span> Real-Time Network Socket Monitor & C2 Radar</div>
          <button class="btn" onclick="fetchNetwork()">SAMPLE SOCKETS</button>
        </div>
        <div class="input-group">
          <input type="text" id="net-target-path" class="text-input" placeholder="Game folder or process name to filter (leave empty for all game sockets)..." />
          <button class="btn btn-cyan" onclick="fetchNetwork()">SCAN CONNECTIONS</button>
        </div>

        <!-- Sockets Table -->
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>PID</th>
                <th>Process Name</th>
                <th>Local Address</th>
                <th>Remote Endpoint</th>
                <th>Category</th>
                <th>Protocol</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="network-tbody">
              <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">Click 'Scan Connections' to inspect active network sockets.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </main>

  <!-- Toast Notification Container -->
  <div class="toast-container" id="toast-container"></div>

  <!-- Vanilla JavaScript Logic -->
  <script>
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Tab Switching
    function switchTab(tabId) {{
      document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      
      const targetPanel = document.getElementById('tab-' + tabId);
      if (targetPanel) targetPanel.classList.add('active');

      const buttons = document.querySelectorAll('.nav-btn');
      const tabIndex = ['dashboard', 'scanner', 'actions', 'vault', 'network'].indexOf(tabId);
      if (tabIndex >= 0 && buttons[tabIndex]) {{
        buttons[tabIndex].classList.add('active');
      }}

      // Sync path inputs
      const currentPath = document.getElementById('quick-target-path').value;
      if (currentPath) {{
        ['scan-target-path', 'action-target-path', 'vault-target-path', 'net-target-path'].forEach(id => {{
          const el = document.getElementById(id);
          if (el && !el.value) el.value = currentPath;
        }});
      }}
    }}

    // Toast Notifications
    function showToast(message, type = 'success') {{
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = `toast toast-${{type}}`;
      
      const icon = type === 'success' ? '&#10003;' : type === 'warning' ? '&#9888;' : '&#10007;';
      toast.innerHTML = `<span style="font-weight:bold; font-size:16px;">${{icon}}</span> <span>${{message}}</span>`;
      container.appendChild(toast);

      setTimeout(() => {{
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(40px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
      }}, 4000);
    }}

    // Console Logging Helper
    function logTerminal(message, type = 'info') {{
      const consoleBox = document.getElementById('terminal-console');
      const time = new Date().toLocaleTimeString();
      let colorClass = 'term-cyan';
      if (type === 'success') colorClass = 'term-green';
      if (type === 'warning') colorClass = 'term-amber';
      if (type === 'error') colorClass = 'term-red';

      consoleBox.innerHTML += `\\n[${{time}}] <span class="${{colorClass}}">${{message}}</span>`;
      consoleBox.scrollTop = consoleBox.scrollHeight;
    }}

    // API Request Wrapper
    async function apiRequest(endpoint, method = 'GET', data = null) {{
      const options = {{
        method,
        headers: {{
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        }}
      }};
      if (data && method !== 'GET') {{
        options.body = JSON.stringify(data);
      }}

      try {{
        const response = await fetch(endpoint, options);
        const json = await response.json();
        if (!response.ok) {{
          throw new Error(json.error || `HTTP error ${{response.status}}`);
        }}
        return json;
      }} catch (err) {{
        showToast(err.message, 'error');
        throw err;
      }}
    }}

    // Status Fetcher
    async function fetchStatus() {{
      try {{
        const data = await apiRequest('/api/status');
        if (data.tools) {{
          const inno = data.tools.innoextract;
          const steamless = data.tools.steamless;
          const sb = data.sandbox_supported;

          document.getElementById('status-inno').innerHTML = inno.available 
            ? '<span class="badge badge-green">VERIFIED</span>' 
            : '<span class="badge badge-amber">PORTABLE FALLBACK</span>';
          document.getElementById('desc-inno').textContent = inno.path || 'Auto-downloads on demand';

          document.getElementById('status-steamless').innerHTML = steamless.available 
            ? '<span class="badge badge-green">AVAILABLE</span>' 
            : '<span class="badge badge-amber">OPTIONAL</span>';
          document.getElementById('desc-steamless').textContent = steamless.path || 'Place in tools/steamless';

          document.getElementById('status-sandbox').innerHTML = sb 
            ? '<span class="badge badge-green">ENABLED</span>' 
            : '<span class="badge badge-red">UNAVAILABLE</span>';
          document.getElementById('desc-sandbox').textContent = sb ? 'Windows Sandbox ready' : 'Hypervisor disabled';

          if (data.quarantine_count !== undefined) {{
            document.getElementById('stat-quar-num').textContent = data.quarantine_count;
          }}
        }}
      }} catch (e) {{
        console.error('Status fetch failed', e);
      }}
    }}

    // Quick Action Handlers
    function startQuickScan() {{
      const path = document.getElementById('quick-target-path').value.trim();
      if (!path) return showToast('Please enter a target path', 'warning');
      document.getElementById('scan-target-path').value = path;
      switchTab('scanner');
      runScan();
    }}

    function startQuickClean() {{
      const path = document.getElementById('quick-target-path').value.trim();
      if (!path) return showToast('Please enter a target path', 'warning');
      document.getElementById('scan-target-path').value = path;
      switchTab('scanner');
      runClean();
    }}

    // Triage Scanner
    async function runScan() {{
      const path = document.getElementById('scan-target-path').value.trim();
      if (!path) return showToast('Please enter a target path to scan', 'warning');

      const pbar = document.getElementById('scan-progress');
      const btn = document.getElementById('btn-scan');
      pbar.classList.add('active');
      btn.disabled = true;

      try {{
        const res = await apiRequest('/api/scan', 'POST', {{ path }});
        renderScanResults(res);
        showToast(`Scan complete: ${{res.total_files}} files analyzed`, 'success');
      }} catch (e) {{
        // Handled in apiRequest
      }} finally {{
        pbar.classList.remove('active');
        btn.disabled = false;
      }}
    }}

    // Clean All Pipeline
    async function runClean() {{
      const path = document.getElementById('scan-target-path').value.trim();
      if (!path) return showToast('Please enter a target path to clean', 'warning');

      const pbar = document.getElementById('scan-progress');
      const btn = document.getElementById('btn-clean');
      pbar.classList.add('active');
      btn.disabled = true;

      try {{
        const res = await apiRequest('/api/clean', 'POST', {{ path }});
        renderCleanResults(res);
        showToast('Full security pipeline applied successfully!', 'success');
      }} catch (e) {{
        // Handled in apiRequest
      }} finally {{
        pbar.classList.remove('active');
        btn.disabled = false;
      }}
    }}

    function renderScanResults(res) {{
      document.getElementById('badge-total-files').textContent = `TOTAL FILES: ${{res.total_files || 0}}`;
      document.getElementById('badge-clean-files').textContent = `CLEAN: ${{res.clean_count || 0}}`;
      document.getElementById('badge-suspicious-files').textContent = `SUSPICIOUS / DRM: ${{res.medium_count || 0}}`;
      document.getElementById('badge-critical-files').textContent = `CRITICAL MALWARE: ${{res.critical_count || 0}}`;

      // Update dashboard telemetry metrics
      document.getElementById('stat-clean').textContent = res.clean_count || 0;
      document.getElementById('stat-clean-num').textContent = res.clean_count || 0;
      document.getElementById('stat-warn').textContent = res.medium_count || 0;
      document.getElementById('stat-warn-num').textContent = res.medium_count || 0;
      document.getElementById('stat-crit').textContent = res.critical_count || 0;

      const tbody = document.getElementById('scan-results-tbody');
      tbody.innerHTML = '';

      if (!res.files || res.files.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">No executable files or scripts found.</td></tr>';
        return;
      }}

      res.files.forEach(f => {{
        const tr = document.createElement('tr');
        let sevBadge = '<span class="badge badge-green">CLEAN</span>';
        if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {{
          sevBadge = '<span class="badge badge-red">' + f.severity + '</span>';
        }} else if (f.severity === 'MEDIUM' || f.severity === 'LOW') {{
          sevBadge = '<span class="badge badge-amber">' + f.severity + '</span>';
        }}

        tr.innerHTML = `
          <td class="mono" style="font-weight: 600; color: #fff;">${{f.file_name}}</td>
          <td class="mono">${{f.architecture || 'Binary'}}</td>
          <td class="mono" style="text-align: center;">${{f.threat_score || 0}}</td>
          <td>${{sevBadge}}</td>
          <td>${{f.verdict || 'Standard Game File'}}</td>
          <td><span class="mono" style="font-size: 11px; color: var(--neon-cyan);">${{f.recommended_action || 'ALLOW'}}</span></td>
        `;
        tbody.appendChild(tr);
      }});

      // Render sideloads
      const sideTbody = document.getElementById('sideload-results-tbody');
      sideTbody.innerHTML = '';
      if (res.sideloads && res.sideloads.length > 0) {{
        res.sideloads.forEach(s => {{
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="mono" style="color: var(--neon-amber); font-weight: 600;">${{s.dll_name}}</td>
            <td><span class="badge badge-amber">${{s.classification}}</span></td>
            <td>${{s.severity}}</td>
            <td class="mono">${{s.target_exe || '-'}}</td>
            <td>${{s.description || 'Potential search-order hijacking'}}</td>
          `;
          sideTbody.appendChild(tr);
        }});
      }} else {{
        sideTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--neon-green); padding: 16px;">&#10003; No suspicious sideloaded proxy DLLs found. Clean search-order.</td></tr>';
      }}
    }}

    function renderCleanResults(res) {{
      renderScanResults({{
        total_files: res.total_files_scanned,
        clean_count: res.clean_files,
        medium_count: res.suspicious_files,
        critical_count: res.critical_threats,
        files: res.file_results,
        sideloads: res.sideload_findings
      }});
      logTerminal(`Clean-All Pipeline Completed! Replaced emulators: ${{res.replaced_emulators?.join(', ') || 'None'}}`, 'success');
      if (res.quarantined_files && res.quarantined_files.length > 0) {{
        logTerminal(`Quarantined threats: ${{res.quarantined_files.join(', ')}}`, 'error');
      }}
    }}

    // Action Execution
    async function executeAction(actionType) {{
      const path = document.getElementById('action-target-path').value.trim() || document.getElementById('quick-target-path').value.trim();
      if (!path) return showToast('Please enter a target path', 'warning');

      logTerminal(`Executing action [${{actionType}}] on: ${{path}}...`);

      try {{
        let endpoint = '';
        let payload = {{ path }};

        if (actionType === 'replace_emulator') endpoint = '/api/emulator/replace';
        else if (actionType === 'shield') endpoint = '/api/shield';
        else if (actionType === 'firewall') endpoint = '/api/firewall';
        else if (actionType === 'sandbox') endpoint = '/api/sandbox';
        else if (actionType === 'snapshot') endpoint = '/api/snapshots/create';

        const res = await apiRequest(endpoint, 'POST', payload);
        logTerminal(`Action completed successfully: ${{JSON.stringify(res)}}`, 'success');
        showToast(`Action ${{actionType}} executed!`, 'success');
      }} catch (e) {{
        logTerminal(`Action failed: ${{e.message}}`, 'error');
      }}
    }}

    // Snapshot Vault
    async function fetchSnapshots() {{
      const path = document.getElementById('vault-target-path').value.trim() || document.getElementById('quick-target-path').value.trim();
      if (!path) return showToast('Please enter a game directory', 'warning');

      try {{
        const res = await apiRequest(`/api/snapshots?path=${{encodeURIComponent(path)}}`);
        const tbody = document.getElementById('snapshots-tbody');
        tbody.innerHTML = '';

        if (!res.snapshots || res.snapshots.length === 0) {{
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No snapshots captured yet for this game.</td></tr>';
          return;
        }}

        res.snapshots.forEach(s => {{
          const tr = document.createElement('tr');
          const kb = Math.round((s.size_bytes || 0) / 1024);
          tr.innerHTML = `
            <td class="mono" style="font-weight: 600; color: var(--neon-cyan);">${{s.snapshot_filename}}</td>
            <td class="mono">${{s.appid || '-'}}</td>
            <td class="mono">${{s.timestamp}}</td>
            <td>${{s.file_count}}</td>
            <td class="mono">${{kb}} KB</td>
            <td>${{s.note || '-'}}</td>
            <td><button class="btn btn-amber" style="padding: 4px 10px; font-size: 11px;" onclick="restoreSnapshot('${{s.snapshot_filename}}')">RESTORE</button></td>
          `;
          tbody.appendChild(tr);
        }});
      }} catch (e) {{}}
    }}

    async function restoreSnapshot(filename) {{
      const path = document.getElementById('vault-target-path').value.trim();
      if (!confirm(`Restore save snapshot '${{filename}}'? Current save state will be backed up.`)) return;

      try {{
        const res = await apiRequest('/api/snapshots/restore', 'POST', {{ path, snapshot: filename }});
        showToast('Snapshot restored successfully!', 'success');
        fetchSnapshots();
      }} catch (e) {{}}
    }}

    async function openSnapshotPrompt() {{
      const path = document.getElementById('vault-target-path').value.trim() || document.getElementById('quick-target-path').value.trim();
      if (!path) return showToast('Please specify a game path first', 'warning');
      const note = prompt('Enter a note or label for this snapshot (e.g., Before Boss Fight):', 'Manual Web Snapshot');
      if (note === null) return;

      try {{
        await apiRequest('/api/snapshots/create', 'POST', {{ path, note }});
        showToast('Snapshot captured!', 'success');
        fetchSnapshots();
      }} catch (e) {{}}
    }}

    // Network Radar
    async function fetchNetwork() {{
      const filter = document.getElementById('net-target-path').value.trim();
      try {{
        const url = filter ? `/api/network?target=${{encodeURIComponent(filter)}}` : '/api/network';
        const res = await apiRequest(url);
        const tbody = document.getElementById('network-tbody');
        tbody.innerHTML = '';

        if (!res.records || res.records.length === 0) {{
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--neon-green); padding: 24px;">&#10003; No suspicious outbound sockets detected. Clean local network.</td></tr>';
          return;
        }}

        res.records.forEach(r => {{
          let catBadge = '<span class="badge badge-cyan">' + r.category + '</span>';
          if (r.category === 'COINMINER_POOL') catBadge = '<span class="badge badge-red">COINMINER POOL</span>';
          else if (r.category === 'PUBLIC_INTERNET') catBadge = '<span class="badge badge-amber">PUBLIC INTERNET</span>';
          else if (r.category === 'PRIVATE_LAN') catBadge = '<span class="badge badge-green">LAN / CO-OP</span>';

          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="mono">${{r.pid}}</td>
            <td style="font-weight: 600; color: #fff;">${{r.process_name}}</td>
            <td class="mono">${{r.laddr}}</td>
            <td class="mono" style="color: var(--neon-cyan);">${{r.raddr || '*'}}</td>
            <td>${{catBadge}}</td>
            <td class="mono">${{r.protocol.toUpperCase()}}</td>
            <td class="mono">${{r.status}}</td>
          `;
          tbody.appendChild(tr);
        }});
      }} catch (e) {{}}
    }}

    // Initial Load
    window.addEventListener('DOMContentLoaded', () => {{
      fetchStatus();
    }});
  </script>
</body>
</html>
"""
