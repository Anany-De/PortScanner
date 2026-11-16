"""Loopback-only performance check; no external hosts are contacted."""
import json
import queue
import socket
import threading
import time
from portscanner import scan


def benchmark():
    with socket.socket() as listener, socket.socket() as closed:
        listener.bind(('127.0.0.1', 0))
        listener.listen(128)
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        open_port = listener.getsockname()[1]
        ports = sorted(set(range(1, 5001)) | {open_port, closed_port})
        events = queue.Queue()
        start = time.perf_counter()
        scan('127.0.0.1', ports, 5.5, threading.Event(), events)
        elapsed = time.perf_counter() - start
        messages = list(events.queue)
        found = [v[0] for k, v in messages if k == 'open']
        assert open_port in found and closed_port not in found
        assert ('progress', len(ports)) in messages
        assert not any(k == 'error' for k, _ in messages)
        return dict(seconds=round(elapsed, 3), ports=len(ports), timeout=5.5,
                    controlled_open_found=True, controlled_closed_absent=True,
                    event_count=len(messages), open_count=len(found))

if __name__ == '__main__':
    print(json.dumps(benchmark()))
