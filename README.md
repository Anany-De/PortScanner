# PortScanner

An offline-capable Python desktop GUI for Windows and Linux, built with Tkinter and the standard library. No third-party Python packages, cloud services, telemetry, or remote assets are required.

## Features

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

## Offline and pen-drive use

Copy the source folder to the destination and create `.venv` using that machine's Python. Virtual environments are not portable between Windows and Linux, Python installations, or moved paths/drive letters; recreate them after moving the project. `.venv` is excluded from Git.

No pip installation is needed. If dependencies are added later, install them through the project interpreter (`.venv\Scripts\python.exe -m pip` on Windows or `.venv/bin/python -m pip` on Linux). Do not install globally.

A standalone Python runtime or executable is not bundled. Once Python/Tk prerequisites are present, the app needs no internet. Hostnames may require DNS; numeric local addresses work without internet.

## Usage

1. Enter one address or hostname, such as `127.0.0.1`. Do not enter a URL or subnet.
2. Enter ports such as `22,80,443` or `1-5000`; commas and ranges can be combined.
3. Set the timeout in seconds (0.05–10), then choose **Start scan** for actual TCP probing.
4. For a local socket snapshot instead, use **Local listeners · no probes** with a numeric IPv4 loopback address.
5. Stop retains partial results. Export CSV saves discovered results and the method/status.

CSV fields: `target`, `port`, `protocol`, `state`, `service_hint`, `connect_ms`, `scan_status`, `method`. Inventory has no connection timing. Exports can contain network details; review them before sharing. Default `portscan*.csv` exports and the `exports/` folder are ignored by Git.

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
.\.venv\Scripts\python.exe -m unittest -v test_portscanner.py
.\.venv\Scripts\python.exe benchmark_local.py
```

Linux:

```sh
.venv/bin/python -m unittest -v test_portscanner.py
.venv/bin/python benchmark_local.py
```

Tests cover real loopback discovery, parsing, timeout preservation, cancellation, resolution and resource failures, inventory filtering, and GUI scanning. Tests require a graphical display and contact only loopback. Benchmarks also contact loopback and may take tens of seconds.

Observed Windows timings for roughly 5,000 ports were about 10.3 seconds for TCP probing at a 0.5-second timeout, versus 0.05–0.09 seconds to render the separate local inventory. Inventory is not a reachability-scan speedup. Timings vary by machine; see [measurement details](PERFORMANCE.md).

## Project files

- `portscanner.py` — desktop GUI and TCP engine.
- `local_inventory.py` — Windows/Linux local IPv4 inventory.
- `Launch.cmd`, `launch.sh` — virtual-environment launchers.
- `test_portscanner.py` — regression checks.
- `benchmark_scan.py`, `benchmark_local.py` — loopback benchmarks.

## Responsible use

Scan only systems you own or have permission to test. Choose ranges and timeouts appropriate to the target; concurrent connection attempts can affect services.

## License

A license has not been selected. No open-source license grant is included yet.
