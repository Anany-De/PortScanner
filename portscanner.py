"""Offline TCP port scanner. Python 3.10+ with Tk support."""
import csv
import ipaddress
from local_inventory import inventory
from assessment import assess
from assessment_ui import ReviewPanel
import errno
import select
from bisect import bisect_left
import queue
import socket
import threading
import time
import tkinter as tk
import tkinter.font
from tkinter import ttk, filedialog, messagebox

BG = '#070b0b'
PANEL = '#101918'
TEXT = '#e8fff5'
MUTED = '#a0bdb0'
ACCENT = '#a3ff12'


def parse_ports(value):
    ports = set()
    for part in value.split(','):
        bounds = part.strip().split('-')
        if len(bounds) not in (1, 2) or any(not p.strip().isdigit() for p in bounds):
            raise ValueError('Use ports like 22,80,443 or a range like 1-1024.')
        low, high = int(bounds[0]), int(bounds[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError('Ports must be between 1 and 65535, in ascending order.')
        ports.update(range(low, high + 1))
    return sorted(ports)


def scan(target, ports, timeout, stop, events):
    """Bounded nonblocking TCP connects; each socket keeps its full timeout."""
    checked = 0
    active = {}
    last_progress = time.monotonic()
    # Under Windows select()'s 512-socket limit, including all three lists.
    concurrency = 256
    in_progress = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                   10035, 10036, 10037}

    def complete(sock, port, started, error):
        nonlocal checked
        sock.close()
        if error in {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EADDRNOTAVAIL, 10024, 10055, 10049}:
            raise OSError(error, 'Local socket resources unavailable; scan incomplete')
        checked += 1
        if error == 0:
            latency = round((time.monotonic() - started) * 1000, 1)
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = 'Unknown'
            events.put(('open', (port, service, latency)))

    try:
        if stop.is_set():
            return
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        family, _, _, _, address = addresses[0]
        events.put(('resolved', address[0]))
        remaining = iter(ports)
        exhausted = False
        while not stop.is_set():
            while len(active) < concurrency and not exhausted and not stop.is_set():
                port = next(remaining, None)
                if port is None:
                    exhausted = True
                    break
                started = time.monotonic()
                sock = socket.socket(family, socket.SOCK_STREAM)
                try:
                    sock.setblocking(False)
                    error = sock.connect_ex((address[0], port, *address[2:]))
                    if error in in_progress:
                        active[sock] = (port, started)
                    else:
                        complete(sock, port, started, error)
                except OSError:
                    sock.close()
                    raise
            if active:
                delay = min(.05, max(0, min(t + timeout for _, t in active.values()) - time.monotonic()))
                _, writable, exceptional = select.select([], list(active), list(active), delay)
                for sock in set(writable) | set(exceptional):
                    port, started = active.pop(sock)
                    complete(sock, port, started, sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))
                now = time.monotonic()
                for sock, (port, started) in list(active.items()):
                    if now - started >= timeout:
                        active.pop(sock)
                        complete(sock, port, started, errno.ETIMEDOUT)
            now = time.monotonic()
            if now - last_progress >= .075:
                events.put(('progress', checked))
                last_progress = now
            if exhausted and not active:
                break
    except (OSError, ValueError) as exc:
        events.put(('error', str(exc)))
    finally:
        for sock in active:
            sock.close()
        events.put(('progress', checked))
        events.put(('done', stop.is_set()))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('PortScanner // Network terminal')
        self.geometry('1160x740')
        self.minsize(1000, 680)
        self.configure(bg=BG)
        self.mono = 'Consolas' if 'Consolas' in tk.font.families(self) else 'DejaVu Sans Mono'
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.rows = []
        self.started = 0
        self.scan_target = ''
        self.resolved_address = ''
        self.local_mode = False
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background=PANEL, foreground=TEXT, font=(self.mono, 10))
        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab', background='#20352b', foreground=TEXT, padding=(14, 8))
        style.map('TNotebook.Tab', background=[('selected', '#345542')], foreground=[('selected', ACCENT)])
        style.configure('TEntry', fieldbackground='#080f0e', foreground=TEXT, insertcolor=TEXT, padding=10)
        style.configure('TButton', padding=(16, 10), background='#20352b', foreground=TEXT, borderwidth=0)
        style.map('TButton', background=[('active', '#345542')], foreground=[('disabled', '#7c978a')])
        style.configure('Accent.TButton', background=ACCENT, foreground='#0c1600', font=(self.mono, 10, 'bold'))
        style.map('Accent.TButton', background=[('active', '#c4ff6a'), ('disabled', '#344528')])
        style.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=40, borderwidth=0)
        style.configure('Treeview.Heading', background='#1b2d25', foreground=MUTED, padding=10, font=(self.mono, 9, 'bold'))
        style.map('Treeview', background=[('selected', '#325737')])
        style.configure('Horizontal.TProgressbar', background=ACCENT, troughcolor='#22362b', borderwidth=0)
        shell = tk.Frame(self, bg=BG, padx=24, pady=16)
        shell.pack(fill='both', expand=True)
        header = tk.Frame(shell, bg=BG)
        header.pack(fill='x')
        self.label(header, '[>] PORTSCANNER', 13, ACCENT, bold=True).pack(side='left')
        self.label(header, 'OFFLINE  //  TCP CONNECT', 9, MUTED).pack(side='right')
        self.label(shell, 'MAP THE ATTACK SURFACE.', 24, bold=True).pack(anchor='w', pady=(14, 4))
        self.label(shell, 'WORK IN PROGRESS // 01 TARGET  /  02 TCP PROBE  /  03 DEFENSIVE REVIEW', 11, MUTED).pack(anchor='w')
        tk.Frame(shell, bg=ACCENT, height=2).pack(fill='x', pady=(12, 0))
        config = tk.Frame(shell, bg=PANEL, padx=16, pady=12)
        config.pack(fill='x', pady=(0, 18))
        config.columnconfigure(0, weight=3)
        config.columnconfigure(1, weight=3)
        config.columnconfigure(2, weight=1)
        self.target = tk.StringVar(value='127.0.0.1')
        self.ports = tk.StringVar(value='1-1024')
        self.timeout = tk.StringVar(value='0.5')
        self.inputs = []
        for col, (caption, variable) in enumerate([('TARGET / HOSTNAME', self.target), ('PORTS / RANGES', self.ports), ('TIMEOUT / SEC', self.timeout)]):
            self.label(config, caption, 9, MUTED, bg=PANEL, bold=True).grid(row=0, column=col, sticky='w', padx=(0, 14), pady=(0, 8))
            entry = ttk.Entry(config, textvariable=variable, width=12)
            entry.grid(row=1, column=col, sticky='ew', padx=(0, 14))
            self.inputs.append(entry)
        actions = tk.Frame(config, bg=PANEL)
        actions.grid(row=2, column=0, columnspan=3, sticky='ew', pady=(14, 0))
        self.start_button = ttk.Button(actions, text='[>] Start scan', style='Accent.TButton', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(actions, text='[X] Stop', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=8)
        self.inventory_button = ttk.Button(actions, text='Local listeners · no probes', command=lambda: self.start(local=True))
        self.inventory_button.pack(side='left')
        ttk.Button(actions, text='Common ports', command=lambda: self.ports.set('21,22,25,53,80,110,139,143,443,445,465,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443')).pack(side='right')
        stats = tk.Frame(shell, bg=BG)
        stats.pack(fill='x')
        self.status = tk.StringVar(value='IDLE // Awaiting target')
        self.count = tk.StringVar(value='0 open ports')
        self.label(stats, '', 11, variable=self.status).pack(side='left')
        self.label(stats, '', 11, ACCENT, variable=self.count, bold=True).pack(side='right')
        self.progress = ttk.Progressbar(shell, mode='determinate')
        self.progress.pack(fill='x', pady=(8, 10))
        toolbar = tk.Frame(shell, bg=BG)
        toolbar.pack(fill='x', pady=(0, 10))
        self.result_heading = tk.StringVar(value='OPEN PORTS · TCP PROBES')
        self.label(toolbar, '', 10, MUTED, bold=True, variable=self.result_heading).pack(side='left')
        self.export_button = ttk.Button(toolbar, text='[↓] Export CSV', command=self.export, state='disabled')
        self.export_button.pack(side='right')
        notebook = ttk.Notebook(shell)
        notebook.pack(fill='both', expand=True)
        table = tk.Frame(notebook, bg=PANEL)
        notebook.add(table, text='  TCP RESULTS / LISTENERS  ')
        self.review = ReviewPanel(notebook, self.mono)
        notebook.add(self.review, text='  DEFENSIVE REVIEW / WARNINGS  ')
        self.tree = ttk.Treeview(table, columns=('port', 'state', 'service', 'latency'), show='headings', selectmode='browse')
        for name, caption, width in [('port', 'PORT / TCP', 130), ('state', 'STATE', 130), ('service', 'SERVICE HINT', 300), ('latency', 'CONNECT TIME', 160)]:
            self.tree.heading(name, text=caption)
            self.tree.column(name, width=width, anchor='w')
        scrollbar = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.tree.tag_configure('even', background=PANEL, foreground=ACCENT)
        self.tree.tag_configure('odd', background='#14221c', foreground=ACCENT)
        self.tree.pack(fill='both', expand=True)
        self.note = tk.StringVar(value='// No results yet. Start a real scan or request a local listener inventory.')
        self.label(shell, '', 9, MUTED, variable=self.note).pack(anchor='w', pady=(12, 0))
        self.label(shell, 'Scan only systems you own or have permission to test.  •  No cloud services or telemetry.', 9, MUTED).pack(anchor='w', pady=(8, 0))
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.poll_job = self.after(75, self.poll)

    def label(self, parent, text, size, color=TEXT, bold=False, bg=BG, variable=None):
        return tk.Label(parent, text=text, textvariable=variable, bg=bg, fg=color, font=(self.mono, size, 'bold' if bold else 'normal'))

    def start(self, local=False):
        if self.running:
            return
        try:
            target = self.target.get().strip()
            if not target or any(c.isspace() for c in target) or '://' in target or '/' in target:
                raise ValueError('Enter one IP address or hostname, without a URL or path.')
            if local:
                ip = ipaddress.ip_address(target)
                if ip.version != 4 or not ip.is_loopback:
                    raise ValueError('Local inventory needs an IPv4 loopback address, such as 127.0.0.1.')
            ports = parse_ports(self.ports.get())
            timeout = float(self.timeout.get())
            if not .05 <= timeout <= 10:
                raise ValueError('Timeout must be between 0.05 and 10 seconds.')
        except ValueError as exc:
            messagebox.showerror('Check scan settings', str(exc))
            return
        self.running = True
        self.failed = False
        self.local_mode = local
        self.result_heading.set('LOCAL LISTENERS · NO PROBES' if local else 'OPEN PORTS · TCP PROBES')
        self.scan_target = target
        self.resolved_address = target
        self.rows.clear()
        self.review.refresh([], 'Starting; no conclusion available')
        self.tree.delete(*self.tree.get_children())
        self.stop_event = threading.Event()
        self.started = time.monotonic()
        self.progress.configure(value=0, maximum=len(ports))
        self.total = len(ports)
        self.count.set('0 listeners' if local else '0 open ports')
        self.status.set('Reading local socket table…' if local else 'Resolving target…')
        self.note.set('Scanning ' + target + ' • Service names are local port-number hints, not verified applications.')
        if local:
            self.note.set('LOCAL INVENTORY · IPv4 listeners only · No connections or firewall/reachability checks.')
        self.inventory_button.configure(state='disabled')
        self.start_button.configure(state='disabled')
        self.export_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        for entry in self.inputs:
            entry.configure(state='disabled')
        threading.Thread(target=inventory if local else scan, args=(target, ports, timeout, self.stop_event, self.events), daemon=True).start()

    def stop(self):
        self.stop_event.set()
        self.status.set('Stopping… waiting for active connections')
        self.stop_button.configure(state='disabled')

    def assessments(self):
        return [assess(port, self.local_mode, self.resolved_address) for port, _, _ in self.rows]

    def poll(self):
        review_dirty = False
        for _ in range(1000):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'resolved':
                self.resolved_address = value
                review_dirty = True
                self.note.set(f'{self.scan_target} → {value} • TCP connect scan • Service names are unverified hints.')
            elif kind == 'open':
                review_dirty = True
                index = bisect_left(self.rows, value)
                self.rows.insert(index, value)
                self.tree.insert('', index, tags=('even' if index % 2 == 0 else 'odd',), values=(value[0], 'Listening' if self.local_mode else '● Open', value[1], 'Not probed' if value[2] is None else f'{value[2]:.1f} ms'))
                self.count.set(f'{len(self.rows)} ' + ('listeners' if self.local_mode else 'open ports'))
            elif kind == 'progress':
                self.progress['value'] = value
                if not self.stop_event.is_set():
                    self.status.set(f'Scanning · {value:,} / {self.total:,} ports')
            elif kind == 'error':
                self.failed = True
                self.note.set('Scan failed: ' + value)
            elif kind == 'done':
                review_dirty = True
                self.running = False
                self.status.set(f'{"Failed" if self.failed else "Stopped" if value else "Finished"} · {int(self.progress["value"]):,} / {self.total:,} ports · {time.monotonic() - self.started:.3f}s')
                self.start_button.configure(state='normal')
                self.inventory_button.configure(state='normal')
                self.stop_button.configure(state='disabled')
                self.export_button.configure(state='normal' if self.rows else 'disabled')
                for entry in self.inputs:
                    entry.configure(state='normal')
        if review_dirty:
            self.review.refresh(self.assessments(), self.status.get())
        self.poll_job = self.after(75, self.poll)

    def export(self):
        path = filedialog.asksaveasfilename(title='Export open ports', defaultextension='.csv', filetypes=[('CSV files', '*.csv')], initialfile='portscan.csv')
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as handle:
                writer = csv.writer(handle)
                writer.writerow(['target', 'port', 'protocol', 'state', 'service_hint', 'connect_ms', 'scan_status', 'method', 'resolved_address', 'review_priority', 'service_inference', 'evidence', 'context', 'confidence', 'condition', 'recommendation', 'vulnerabilities', 'source', 'reviewed'])
                for port, service, latency in self.rows:
                    guidance = assess(port, self.local_mode, self.resolved_address)
                    writer.writerow([self.scan_target, port, 'TCP', 'listening' if self.local_mode else 'open', service, latency, self.status.get(), 'local_inventory_no_probes' if self.local_mode else 'tcp_connect', self.resolved_address, *[guidance[key] for key in ('review_priority', 'service_inference', 'evidence', 'context', 'confidence', 'condition', 'recommendation', 'vulnerabilities', 'source', 'reviewed')]])
            self.note.set('Exported ' + path)
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))

    def close(self):
        self.stop_event.set()
        if getattr(self, 'poll_job', None):
            self.after_cancel(self.poll_job)
        self.destroy()


if __name__ == '__main__':
    App().mainloop()
