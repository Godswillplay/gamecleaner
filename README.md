# GameCleaner 🛡️🎮

**GameCleaner** is an automated security triage, malware isolation, and containment framework for untrusted or cracked games and software.

When users download cracked games or repacks, they frequently face two major problems:
1. **Hostile Trojans & Stealers:** Shady repacks often bundle silent infostealers (e.g. Lumma, Redline, Vidar), XMRig cryptominers, or secondary droppers.
2. **False Positives vs. Real Threats:** Antivirus heuristics flag all crack hooks (`steam_api64.dll`, memory injectors) as generic `HackTool` or `Riskware`, making it difficult to distinguish harmless DRM emulators from dangerous malware.

**GameCleaner solves this through a 3-pillar defense pipeline:**
- **Pillar 1 — Deep Static PE & Heuristic Triage:** Analyzes PE headers, section entropy (detecting packers/crypters), sensitive Windows API imports (credential theft, process injection, keylogging), and payload signatures. Queries VirusTotal by hash to separate `HackTool` heuristics from confirmed malware families.
- **Pillar 2 — Clean-Room Emulator Replacement:** Untrusted, closed-source cracked DLLs (such as shady `steam_api64.dll` files) can be safely backed up and replaced with audited, open-source clean emulators (e.g. Goldberg Steam Emulator).
- **Pillar 3 — OS Firewall Isolation & Air-Gapped Sandbox:** Automatically generates Windows Firewall rules blocking all outbound/inbound traffic for game executables (preventing credential exfiltration and C2 beaconing) and generates a one-click **Windows Sandbox (`.wsb`)** profile with virtualized 3D GPU acceleration.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────┐
                      │    Untrusted Game Directory / Repack │
                      └──────────────────┬───────────────────┘
                                         │
                   ┌─────────────────────▼─────────────────────┐
                   │ Pillar 1: Static PE & Threat Triage       │
                   │ • Section Entropy (Crypter Detection)     │
                   │ • Sensitive API Imports (Stealers/Miners) │
                   │ • String Signatures (Webhooks/Tokens)     │
                   │ • VirusTotal Threat Family Analysis       │
                   └─────────────────────┬─────────────────────┘
                                         │
         ┌───────────────────────────────┼──────────────────────────────┐
         ▼                               ▼                              ▼
┌──────────────────┐           ┌────────────────────┐         ┌────────────────────┐
│ Clean Binaries   │           │ Untrusted DRM Hook │         │ Hostile Payload    │
│ (Retain & Verify)│           │ (e.g. steam_api64) │         │ (Stealer / Miner)  │
└────────┬─────────┘           └─────────┬──────────┘         └─────────┬──────────┘
         │                               │                              │
         │                     ┌─────────▼──────────┐         ┌─────────▼──────────┐
         │                     │ Pillar 2: Clean    │         │ Quarantine Vault   │
         │                     │ Emulator Replace   │         │ (.gamecleaner_     │
         │                     │ (Goldberg Emu)     │         │  quarantine/)      │
         │                     └─────────┬──────────┘         └────────────────────┘
         │                               │
         └───────────────────────────────┴──────────────────────────────┐
                                                                        ▼
                                                   ┌────────────────────────────────────────┐
                                                   │ Pillar 3: Network Isolation & Sandbox  │
                                                   │ • Windows Firewall Outbound Blocks     │
                                                   │ • Air-Gapped Windows Sandbox (.wsb)    │
                                                   └────────────────────────────────────────┘
```

---

## Installation

### Prerequisites
- Windows 10 / 11 (64-bit)
- Python 3.8+

### Setup
```powershell
git clone https://github.com/your-username/gamecleaner.git
cd gamecleaner
pip install -e .
```

Dependencies installed: `pefile`, `rich`, `requests`.

---

## Usage

### 1. Run the Full Security Pipeline (`clean-all`)
Performs the complete automated audit: scans binaries, quarantines hostile payloads, replaces untrusted DRM hooks with clean open-source emulators, generates network firewall blocking scripts, creates an air-gapped sandbox profile, and generates `gamecleaner_report.md`.

```powershell
gamecleaner clean-all "D:\Games\MyGameFolder"
```

Options:
- `--no-quarantine`: Skip moving critical threats to the quarantine vault.
- `--no-replace-emu`: Skip replacing Steam DRM hooks with Goldberg.
- `--no-firewall`: Skip generating firewall isolation scripts.
- `--no-sandbox`: Skip generating `.wsb` sandbox configuration.

---

### 2. Scan and Triage Only (`scan`)
Inspects all `.exe` and `.dll` files in a folder and outputs a color-coded triage table with threat scores (0–100), section entropy, signature validity, and verdicts.

```powershell
gamecleaner scan "D:\Games\MyGameFolder"
```

Optional: Set your VirusTotal API key to check threat intelligence feeds:
```powershell
$env:VT_API_KEY="your_virustotal_api_key"
gamecleaner scan "D:\Games\MyGameFolder"
```

---

### 3. Replace Untrusted DRM Hooks with Clean Emulators (`replace-emu`)
Scans for `steam_api.dll` and `steam_api64.dll`, backs them up safely to `.gamecleaner_backup/`, and swaps them with verified clean open-source Goldberg emulators.

```powershell
gamecleaner replace-emu "D:\Games\MyGameFolder"
```

You can also provide your own compiled/audited clean DLL:
```powershell
gamecleaner replace-emu "D:\Games\MyGameFolder" --custom-dll "C:\path\to\clean_steam_api64.dll"
```

---

### 4. Firewall Network Isolation (`firewall`)
Generates `block_game_network.ps1` and `unblock_game_network.ps1` in the game directory. 
Executing `block_game_network.ps1` as Administrator adds Windows Firewall rules that completely block outbound and inbound network traffic for every executable in the folder.

```powershell
gamecleaner firewall "D:\Games\MyGameFolder"
```
> **Why this matters:** Offline single-player games never need internet. Blocking outbound traffic neutralizes infostealer exfiltration, C2 beacons, and background cryptominers even if an undetected script is present.

---

### 5. Windows Sandbox Isolation (`sandbox`)
Generates an air-gapped `Sandbox_<GameName>.wsb` file.

```powershell
gamecleaner sandbox "D:\Games\MyGameFolder"
```
Double-clicking the `.wsb` file starts an isolated, throwaway Windows virtual machine with:
- `<Networking>Disable</Networking>` (fully air-gapped).
- `<VGpu>Enable</VGpu>` (DirectX/Vulkan hardware acceleration enabled for 3D games).
- The game folder mounted to `C:\TestingGame` in read-only mode.

---

## Running Tests

```powershell
python -m unittest discover tests
```

---

## Project Structure

```
gamecleaner/
├── gamecleaner/
│   ├── analyzer/
│   │   ├── pe_scanner.py         # PE headers, imports, entropy, threat score
│   │   ├── threat_rules.py       # API signatures (stealer/miner/dropper rules)
│   │   └── virustotal.py         # VirusTotal v3 API hash lookup
│   ├── cleaner/
│   │   ├── quarantine.py         # Safe file isolation and restore manager
│   │   └── emu_replacer.py       # Goldberg clean emulator installer & backup
│   ├── containment/
│   │   ├── firewall.py           # Windows Firewall isolation script generator
│   │   └── sandbox.py            # Windows Sandbox (.wsb) generator
│   ├── pipeline.py               # Full end-to-end orchestration
│   └── cli.py                    # Rich CLI command interface
├── tests/
│   ├── test_gamecleaner.py       # Unit tests for individual components
│   └── test_pipeline_e2e.py      # End-to-end integration test
├── setup.py
└── README.md
```

## Security & Ethics Notice
GameCleaner is a defensive security triage and quarantine tool designed to protect users' personal systems from malware, trojans, and surveillance payloads frequently bundled in third-party downloads. It does not generate malware or crack games.
