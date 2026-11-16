<div align="center">

# `[>] PORTSCANNER`
### LOCAL FIRST. EVIDENCE FIRST.

**Cyber-terminal desktop scanner · Windows + Linux · Python + Tkinter**

![Status: Work in progress](https://img.shields.io/badge/status-WORK_IN_PROGRESS-a3ff12?style=for-the-badge&labelColor=101918)
![Runtime: Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-70d8ff?style=for-the-badge&labelColor=101918)
[![License: MIT](https://img.shields.io/badge/license-MIT-a3ff12?style=for-the-badge&labelColor=101918)](LICENSE)
![Dependencies: Standard library](https://img.shields.io/badge/dependencies-STANDARD_LIBRARY-bcb7ff?style=for-the-badge&labelColor=101918)

**[Quick start](#windows-setup) · [Scan modes](#features) · [Defensive review](#defensive-service-review-experimental) · [Checks](#verification-and-benchmarks) · [Roadmap](#roadmap)**

</div>

---

> **WORK IN PROGRESS / IN DEVELOPMENT** — experimental desktop tool, not a stable release or a verified vulnerability scanner. Windows checks pass; Linux execution remains unverified.

An offline-capable Python desktop GUI for Windows and Linux, built with Tkinter and the standard library. No third-party Python packages, cloud services, telemetry, or remote assets are required.

**Offline / local:** scan your own localhost or reachable local-network systems without internet; the local-listener inventory is limited to your own computer.

**Online / external:** scan reachable external IPs or hostnames with network connectivity. This checks TCP service reachability, not a full website vulnerability audit. **Scan only systems you own or have explicit permission to test, within the authorized scope. Public availability is not permission.**

## Features

- Cyber-terminal styling with local monospace fonts, neon accents and readable controls.
- Offline defensive-review chart, selectable evidence and remediation guidance with bundled source links.
- Dark desktop interface with target, port ranges, connection timeout, progress, and Stop controls.
- Real TCP connect scans for a single IPv4/IPv6 address or hostname, with up to 256 concurrent connections.
- Explicit **Local listeners · no probes** action for fast IPv4 loopback socket inventory.
- Sorted results with local service-name hints and connection timing.
- CSV export that identifies the method, result state, and completion/partial-scan status.

| Action | What it reports | Limits |
| --- | --- | --- |
| Start scan | Successful TCP connections, labeled Open | Uses the full selected per-connection timeout |
| Local listeners · no probes | OS listening sockets, labeled Listening / Not probed | Numeric IPv4 loopback only; does not test reachability or firewall rules |

## Windows setup

Install Python 3.10 or newer with Tcl/Tk support. Open a terminal in the project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m tkinter
.\Launch.cmd
```

The Tk command opens a small test window; close it before launching. After setup, double-click `Launch.cmd` to run the application. The launcher uses the project-local virtual environment.

## Linux setup

Install Python 3.10 or newer, Tk, and venv support before going offline. Debian/Ubuntu typically provide Tk and venv as `python3-tk` and `python3-venv`.

```sh
python3 -m venv .venv
.venv/bin/python -m tkinter
sh launch.sh
```

A graphical desktop is required. Close the Tk test window before launching. The shell launcher does not need an executable permission bit when run with `sh`.

## Offline operation and Python environments

Clone or download the project and create `.venv` using your system's Python. Recreate the environment separately for each operating system, Python installation, or changed project path. `.venv` is excluded from Git.

No pip installation is needed. If dependencies are added later, install them through the project interpreter (`.venv\Scripts\python.exe -m pip` on Windows or `.venv/bin/python -m pip` on Linux). Do not install globally.

A standalone Python runtime or executable is not bundled. Once Python/Tk prerequisites are present, the app needs no internet. Hostnames may require DNS; numeric local addresses work without internet.

## Usage

1. Enter one address or hostname, such as `127.0.0.1`. Do not enter a URL or subnet.
2. Enter ports such as `22,80,443` or `1-5000`; commas and ranges can be combined.
3. Set the timeout in seconds (0.05–10), then choose **Start scan** for actual TCP probing.
4. For a local socket snapshot instead, use **Local listeners · no probes** with a numeric IPv4 loopback address.
5. Stop retains partial results. Export CSV saves discovered results and the method/status.

CSV includes target/resolved address, TCP state, service hint, timing, scan status/method, conditional review priority, evidence, confidence, recommendations, vulnerability-assessment status, source link and review date. Inventory has no connection timing. Exports can contain network details; review them before sharing. Default `portscan*.csv` exports and the `exports/` folder are ignored by Git.

## Limitations

- A TCP scan resolves a hostname once and scans the first returned address. Use an explicit IP to select an address family or interface.
- Only successful connections appear as Open. An omitted port may have timed out, been blocked, or failed for another reason; it is not necessarily closed.
- Service names are port-number hints, not verified application identification. Connect time is not an ICMP ping.
- Stop closes active probes promptly after resolution; OS DNS resolution cannot be interrupted immediately.
- Inventory is a momentary IPv4 OS snapshot, matching the target loopback address and wildcard binds. It excludes IPv6/dual-stack-only table entries. Linux inventory sees the current network namespace.
- UDP, service fingerprinting, saved scan history, and standalone executable packaging are not included.
- Windows execution has been tested with Python 3.14. Linux paths are implemented but have not been executed on a Linux host.

## Verification and benchmarks

Windows:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe benchmark_local.py
```

Linux:

```sh
.venv/bin/python -m unittest discover -v
.venv/bin/python benchmark_local.py
```

Tests cover real loopback discovery, parsing, timeout preservation, cancellation, resolution and resource failures, inventory filtering, and GUI scanning. Tests require a graphical display and contact only loopback. Benchmarks also contact loopback and may take tens of seconds.

Observed Windows timings for roughly 5,000 ports were about 10.3 seconds for TCP probing at a 0.5-second timeout, versus 0.05–0.09 seconds to render the separate local inventory. Inventory is not a reachability-scan speedup. Timings vary by machine; see [measurement details](PERFORMANCE.md).

## Project files

- `portscanner.py` — desktop GUI and TCP engine.
- `local_inventory.py` — Windows/Linux local IPv4 inventory.
- `Launch.cmd`, `launch.sh` — virtual-environment launchers.
- `assessment.py`, `assessment_ui.py` — bundled guidance catalog and review dashboard.
- `test_portscanner.py`, `test_assessment.py` — regression checks.
- `benchmark_scan.py`, `benchmark_local.py` — loopback benchmarks.

## Responsible use

Scan only systems you own or have permission to test. Choose ranges and timeouts appropriate to the target; concurrent connection attempts can affect services.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 Anany-De.

MIT permits reuse, modification and redistribution, including commercial use, provided the copyright and permission notice are retained. The software is provided without warranty. Contributions can be proposed through pull requests; the license does not grant repository write access.

The license applies to this project's original code and documentation. External reference documents and Shields.io badge assets remain under their respective owners' terms; they are not relicensed here. Python/Tk runtimes are not bundled and retain their own licenses.

## Defensive service review (experimental)

The **Defensive review / warnings** tab summarizes observed services by conditional review task: Restrict access, Review configuration, Identify service, or Local review. Select a row for observed evidence, inferred service, confidence, risk conditions, defensive recommendations, source URL and review date. These are review priorities, not vulnerability severity or proof of exploitability. Unknown ports receive identification guidance; they are not assumed safe.

TCP results work for your own localhost, reachable local-network hosts without internet, and external IPs/hostnames you are authorized to test. External targets require working networking; offline operation cannot reach internet hosts. Address context is based on the resolved IP, not proof of public exposure. A successful connection proves reachability only from the scanning computer at that moment. Inventory is a separate local OS snapshot with remote reachability not assessed.

Service identity is only a port-number guess. No version identification, CVE matching, TLS/authentication verification, banner collection, exploitation, credential guesses, login attempts or automatic firewall changes are performed. **Verified vulnerabilities: not assessed.** Missing results and partial scans do not establish safety. Guidance is bundled in `assessment.py`, reviewed 2026-11-17; links are references, not runtime network dependencies. Sources can change after review. CSV exports include all assessment fields and the resolved address alongside method and scan status.

Implemented: TCP scanning, local listener inventory, offline conditional guidance and chart, source-backed detail, CSV export. Tested on Windows using controlled loopback sockets and synthetic assessment inputs; no external targets were probed for development verification. Not verified: Linux execution, real-world configuration/vulnerability detection, or suitability as a security audit.

Catalog sources: [CISA ransomware guide](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C_.pdf), [FBI RDP guidance](https://www.ic3.gov/PSA/2018/PSA180927), [Microsoft SMB protection](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic), [Redis security](https://redis.io/docs/latest/manual/security/), [PostgreSQL authentication](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html), [OpenSSH configuration](https://man.openbsd.org/sshd_config), [OWASP TLS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

## Development status

| Capability | Current status |
| --- | --- |
| TCP probes, Stop, progress, CSV | Implemented; Windows loopback checks |
| Local IPv4 listener inventory | Implemented; Windows checked; Linux unverified |
| Conditional service guidance and dashboard | Implemented, experimental; synthetic evidence/export checks |
| Offline native launch | Standard library; host Python/Tk required |
| Linux GUI / performance | Implemented, execution validation pending |
| Version/CVE detection or verified vulnerabilities | Not implemented; explicitly not assessed |
| Standalone executables | Not bundled |

This is an **in-development project**, not a security certification or stable release. Badges describe project properties, not passing CI. README badge images are hosted by Shields.io; the application has no dependency on those images or internet access.

## Roadmap

- [ ] Validate the GUI, inventory and networking on Linux.
- [ ] Improve keyboard navigation, resizing and accessibility across platforms.
- [ ] Expand the reviewed offline service catalog with careful evidence labeling.
- [ ] Evaluate standalone Windows/Linux builds.
- [ ] Add broader test automation and document reproducible platform checks.

No Docker runtime is required or planned for the current native launch path. Project source is available under the [MIT License](LICENSE).
