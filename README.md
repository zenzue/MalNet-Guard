# MalNet Guard
**Author:** w01f • **Purpose:** Detect signs of malware infection and data exfiltration by auditing active network connections across Windows, Linux, and macOS.

## Highlights
- Cross‑platform via `psutil`; gracefully falls back to parsing `ss`/`netstat` if available.
- Checks foreign addresses against local allow/block lists and (optionally) cloud reputation services (AbuseIPDB, VirusTotal).
- Heuristics for exfiltration (unusual ports, bursts of outbound bytes), suspicious listeners, and hidden/orphan sockets (Linux).
- Outputs human‑readable table + JSON, with CI‑friendly exit codes.

## Install
```bash
pip install -r requirements.txt
```

## Quick Start
```bash
python malnet_guard.py --top 50 --exfil-check --orphan-check --json-out report.json
```

### Optional cloud reputation
Set one (or both) of these env vars to enable remote scoring:
```bash
export ABUSEIPDB_API_KEY=xxxxx
export VT_API_KEY=xxxxx
python malnet_guard.py --cloud-reputation
```

## What the scores mean
- **Risk ≥ 50**: strong indicator (blocklist hit, suspicious port + bad reputation, orphan listener).
- **10 ≤ Risk < 50**: worth reviewing (non‑standard ports, long‑lived TCP ESTAB to public IPs).
- **< 10**: generally benign unless you know otherwise.

## Exfiltration notes
Per‑connection byte counts are OS‑specific and not always available without kernel hooks. MalNet Guard uses a short window sampler of **total interface bytes** combined with the current set of **active outbound connections** and **suspicious ports** to raise a flag quickly. Tune thresholds in `rules.yaml` for your environment.

## Hidden ports / sockets (Linux)
`--orphan-check` attempts to find TCP **LISTEN** sockets whose inodes are not owned by any userland process (a common sign of rootkits / LD_PRELOAD hiding). This is best‑effort and may require root.

## Outputs
- **Console table**: sorted by descending risk.
- **JSON** (`--json-out report.json`): full machine‑readable report including exfil + orphan hints.
- **Exit codes**: `0` OK, `2` risky connections found (≥ 50). Useful in EDR/CI.

## Recommended hardening & triage
1. Terminate unknown processes binding to suspicious ports (check `proc` column + `pid`).
2. If remote IP is flagged by reputation, capture PCAP, block at firewall, and investigate logs.
3. For exfil bursts, isolate host and review recent process execution, USB insertions, and browser extensions.
4. On Linux, compare `/proc/net/*` vs `lsof -i` for discrepancies. On Windows, compare `netstat -ano` vs Sysmon logs.

## License
MIT


## New: ARP spoof / NetCut detection
Use `--arp-check` to analyze the ARP table and flag symptoms of ARP spoofing / "internet cut":
- Default gateway MAC anomalies (missing or claiming many IPs)
- A single MAC answering for many LAN IPs (≥10) — common in NetCut-style attacks
- Summary printed + JSON report under `arp_analysis`

## New: Connectivity symptom test
Adds a quick WAN reachability test. If LAN IP is present but WAN TCP connects all fail, the tool reports
"LAN up but WAN blocked — possible NetCut/ARP disruption." Result under `connectivity` in JSON.

## Optional: Shodan enrichment
Provide `SHODAN_API_KEY` in `.env` and use `--shodan` to attach tags and common open ports observed by Shodan for remote IPs.

## .env configuration
Create a `.env` file or use the provided `.env-example`:
```env
ABUSEIPDB_API_KEY=
VT_API_KEY=
SHODAN_API_KEY=
# Optionally point to a different env path
# DOTENV_PATH=/etc/malnet_guard.env
```


## Security Features & Plugin Explanations

MalNet Guard is modular. Each option corresponds to a **plugin-like feature**. Here’s why each exists and when to use it:

### 1. Connection Collector (default)
- **Purpose:** Gather all TCP/UDP sockets from the OS.
- **Why:** Malware usually needs a network connection. By monitoring sockets, we catch both inbound (C2 listeners) and outbound (exfiltration, beaconing) attempts.
- **Cross-Platform:** Uses `psutil` (preferred) but falls back to `ss`/`netstat`.

### 2. Reputation Lookups (`--cloud-reputation`)
- **Purpose:** Score remote IPs against **AbuseIPDB** or **VirusTotal**.
- **Why:** Known-bad IPs are strong infection indicators. Cloud scoring complements local heuristics.

### 3. Heuristics Engine (always on)
- **Purpose:** Apply scoring rules from `rules.yaml`.
- **Why:** Ports, TCP states, ownership, and anomalies each raise suspicion levels. Flexible scoring enables tuning for different environments.

### 4. Exfiltration Window (`--exfil-check`)
- **Purpose:** Sample outbound bytes over a short period.
- **Why:** Detects **large data bursts** on unusual ports, an early sign of exfiltration or tunneling.

### 5. Orphan Listener Check (`--orphan-check`)
- **Purpose:** Compare `/proc/net` sockets vs process table (Linux only).
- **Why:** Hidden or orphaned listeners may signal **rootkits** or malware using LD_PRELOAD tricks.

### 6. ARP Spoof Detector (`--arp-check`)
- **Purpose:** Analyze ARP cache for anomalies.
- **Why:** Defends against **MITM tools like NetCut**, where attackers spoof gateway MAC or claim many IPs. Reports suspicious MAC addresses.

### 7. Connectivity Symptom Test (always on)
- **Purpose:** Check LAN vs WAN connectivity.
- **Why:** Identifies **“internet cut” attacks** where LAN is fine but WAN traffic is blocked (common with Wi-Fi hijacking/ARP spoof).

### 8. Shodan Enrichment (`--shodan`)
- **Purpose:** Query Shodan for remote IP metadata (tags, ports).
- **Why:** Adds OSINT visibility — if a remote host is flagged or exposes sensitive services, it increases risk.

### 9. .env Secrets
- **Purpose:** Store API keys (`AbuseIPDB`, `VirusTotal`, `Shodan`) in `.env` rather than environment variables or code.
- **Why:** Separation of secrets prevents leaks and simplifies deployment.

---

### Security Posture
MalNet Guard is **read-only** by design (safe to run on production endpoints). It doesn’t terminate connections or alter routing, ensuring no accidental downtime. Exit codes (`0` safe, `2` risky) let you embed it into CI/CD pipelines or EDR triage.



---
## Plugin System
MalNet Guard loads any `plugins/*.py` that exposes a `Plugin(PluginBase)` class. Each plugin receives:
- `rules`: merged `rules.yaml`
- `rows`: the connection list scored by the core
- `report`: the full report dictionary

Results are stored under `report["plugins"][<plugin_name>]`. Any plugin may set `critical: true` to influence the exit code.

### Built-in Plugins (and why to use them)

1) **dns_resolver_health**
   - **What it does:** Reads `/etc/resolv.conf` (or `nslookup` on Windows) to list active resolvers; optionally enforces a corporate-DNS policy.
   - **Why:** Malware and rogue Wi‑Fi tools often change DNS to bypass filtering or hijack traffic. Public resolvers on a corp device may violate policy or indicate tampering.
   - **Rules:** `plugins.dns_resolver_health.require_corporate_dns` (default false).

2) **firewall_posture**
   - **What it does:** Checks host firewall state on Linux (`ufw`, `firewalld`), macOS (`pfctl`), Windows (`netsh advfirewall`).
   - **Why:** A disabled firewall increases exposure to lateral movement and backdoors.
   - **Critical:** Marks critical if firewall is disabled.

3) **autoruns_overview**
   - **What it does:** Lists common autorun locations (`cron`, `systemd`, `launchd`, Windows Run keys).
   - **Why:** Persistence is a hallmark of malware; these launch points should be reviewed.

4) **gateway_mac_allowlist**
   - **What it does:** Compares ARP-resolved default gateway MAC with an allowlist.
   - **Why:** Detects rogue APs/mitm when the gateway MAC suddenly changes.
   - **Rules:** `plugins.gateway_mac_allowlist.allowed_macs` (array).

### Enabling/Disabling Plugins
Update `rules.yaml` under `plugins:<name>:enabled`.

### .env Keys (recap)
- `ABUSEIPDB_API_KEY` — optional reputation scoring
- `VT_API_KEY` — optional VirusTotal enrichment
- `SHODAN_API_KEY` — optional Shodan tags/ports
- `DOTENV_PATH` — optional path to your `.env`

### Security Features Recap (core + plugins)
- **ARP/NetCut Detection:** `--arp-check`, gateway MAC analysis, duplicate IP claims per MAC.
- **Connectivity Symptom Test:** LAN vs WAN quick test to spot ARP-based “internet cut” disruptions.
- **Reputation & Enrichment:** Local allow/block lists + AbuseIPDB/VT/Shodan (opt-in).
- **Hidden Ports (Linux):** Orphan inodes for LISTEN sockets suggest stealth/rootkit behavior.
- **Firewall Posture:** Ensures host firewall is not silently disabled.
- **Autoruns Overview:** Surfaces persistence footholds for investigation.


5) **process_image_integrity**
   - **What it does:** Hashes running process executables and compares to an allowlist.
   - **Why:** Unknown or tampered binaries are a major sign of compromise.

6) **tls_inspection**
   - **What it does:** Connects to remote IP:443 and inspects the TLS certificate CN/SAN.
   - **Why:** Detects MITM or interception if SNI does not match CN/SAN.

7) **gateway_drift_monitor**
   - **What it does:** Samples the system's default gateway twice to see if it changes.
   - **Why:** Gateway/DHCP drift can reveal DHCP spoofing or rogue routers.


5) **process_image_integrity**
   - **What it does:** Hashes running process executables (SHA-256) and compares against an allowlist.
   - **Why:** Unknown binaries in memory are a strong indicator of compromise or shadow IT.
   - **Rules:** `plugins.process_image_integrity.allow_hashes: [ "sha256...", ... ]`
   - **Notes:** Requires `psutil`. If allowlist is empty, results are informational.

6) **tls_inspection**
   - **What it does:** For active TCP connections on 443/8443, fetches the server certificate and checks for empty SAN/CN.
   - **Why:** Empty or generic certificates can indicate TLS interception/misconfiguration during exfil or C2.
   - **Caveat:** Client SNI is not observable without packet capture; this is a best‑effort heuristic.

7) **dhcp_gateway_drift**
   - **What it does:** Stores the gateway IP/MAC at `~/.malnet_guard_state.json` and flags changes across runs.
   - **Why:** Drift can indicate DHCP poisoning, rogue APs, or network reconfiguration used by attackers.
   - **Critical:** Marks critical when drift is detected.
