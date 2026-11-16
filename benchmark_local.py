"""Compare TCP probing with explicitly different local inventory, including GUI time."""
import queue
import socket
import statistics
import threading
import time
from portscanner import App, scan
from local_inventory import inventory

with socket.socket() as opened, socket.socket() as closed:
    for port in range(4500, 5000):
        try:
            opened.bind(('127.0.0.1', port))
            break
        except OSError:
            continue
    opened.listen(128)
    closed.bind(('127.0.0.1', 0))
    closed_port = closed.getsockname()[1]
    ports = list(range(1,5001)) + [closed_port]
    for method in [scan, inventory]:
        samples=[]
        for _ in range(1 if method is scan else 5):
            events=queue.Queue()
            start=time.perf_counter()
            method('127.0.0.1', ports, .5, threading.Event(), events)
            samples.append(time.perf_counter()-start)
            found={v[0] for k,v in list(events.queue) if k=='open'}
            assert opened.getsockname()[1] in found
            assert closed_port not in found
            assert not any(k=='error' for k,v in list(events.queue))
        print(method.__name__, 'seconds:', [round(x,4) for x in samples], flush=True)
    app=App()
    app.update()
    app.ports.set('1-5000')
    samples=[]
    try:
        for _ in range(5):
            start=time.perf_counter()
            app.start(local=True)
            while app.running and time.perf_counter()-start<5:
                app.update()
                time.sleep(.001)
            assert not app.running and not app.failed
            assert any(row[0]==opened.getsockname()[1] for row in app.rows)
            assert all(app.tree.item(i,'values')[1]=='Listening' for i in app.tree.get_children())
            samples.append(time.perf_counter()-start)
        print('GUI local inventory start-to-render seconds:', [round(x,4) for x in samples], flush=True)
    finally:
        app.close()
