# Performance measurements

## Performance verification (Windows)

Loopback benchmark on this machine, scanning ports 1–5000 plus a controlled open and closed port, with the same **5.5-second timeout**:

- Original 64-thread engine: **160.785 seconds**, 2,336 queued events.
- New 256-connection nonblocking engine: **40.846 seconds**, 353 queued events (about **3.94× faster**).
- Both detected the controlled listening port and excluded the controlled closed port; each found three open ports in that run.
- At the unchanged GUI default of **0.5 seconds**, the optimized engine scanned ports 1–5000 in **10.288 seconds**.

These are single-run local measurements, not universal guarantees. Baseline and optimized runs partially overlapped. Windows socket refusal/retry behavior and local security software can cause localhost connections to take time. A 5.5-second timeout can still require multiple connection waves; it has not been silently shortened. Higher concurrency uses more sockets and may affect heavily loaded targets. Linux performance has not been measured.

Reproduce the controlled localhost check using `.venv\Scripts\python.exe benchmark_scan.py` (or `.venv/bin/python benchmark_scan.py` on Linux). Regression tests also verify that pending connections keep their complete timeout and that Stop closes active sockets without waiting for that timeout.

## Fast localhost inventory

For an immediate local view, enter `127.0.0.1` and click **Local listeners · no probes**. This is an explicit alternative to **Start scan**, which still makes actual TCP connections and respects the selected timeout.

Inventory reads Windows GetTcpTable or Linux `/proc/net/tcp`. It supports numeric IPv4 loopback targets only, filters by the requested ports and exact loopback/wildcard bind address, and shows **Listening / Not probed**. CSV includes `state=listening` and `method=local_inventory_no_probes`; actual scans use `state=open` and `method=tcp_connect`. Inventory is a momentary OS snapshot: it does not test firewall policy, connection acceptance, or reachability, and does not include IPv6/dual-stack-only table entries. Use Start scan to test those cases. Linux results are limited to the current network namespace. Read failures are reported; there is no silent fallback to probing.

Additional Windows measurements with a controlled listener and a bound non-listening socket, using ports 1–5000 plus the non-listening port:

- TCP probing at the unchanged 0.5-second timeout: **10.2676 seconds**.
- OS inventory, five runs: **0.0097, 0.0046, 0.0025, 0.0058, 0.0029 seconds**.
- Inventory from GUI action through result rendering, five runs: **0.0626, 0.0802, 0.0749, 0.0713, 0.0862 seconds** (excludes application startup).
- Each method found the controlled IPv4 listener and excluded the non-listening socket. These methods answer different questions; their timings are not equivalent reachability-scan speedups.

A separate controlled closed localhost connection took **2.0419 seconds** for Windows to report refusal. Thus a guaranteed 0.25-second total TCP reachability scan cannot be promised while preserving full per-connection waits. The fast inventory meets that target on this machine by reading OS state instead. No concurrency increase or timeout reduction was applied in this change. Local socket resource errors now explicitly fail the scan as incomplete.

Run `.venv\Scripts\python.exe benchmark_local.py` to reproduce the local comparison. Eight regression tests cover the scanner, inventory filtering, controlled listeners, cancellation, timeout preservation, GUI probing, and resource errors. Linux inventory is implemented but has not been executed on this Windows host.

API reference: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcptable
