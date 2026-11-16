"""Offline assessment presentation. Priorities describe review tasks, not severity."""
import tkinter as tk
from tkinter import ttk

COLORS = {'Restrict access': '#ffbc66', 'Review configuration': '#a3ff12',
          'Identify service': '#70d8ff', 'Local review': '#bcb7ff'}


class ReviewPanel(tk.Frame):
    def __init__(self, parent, mono):
        super().__init__(parent, bg='#101918', padx=14, pady=12)
        self.items = {}
        self.summary = tk.StringVar(value='No observed results. No security conclusion is available.')
        tk.Label(self, text='CONDITIONAL EXPOSURE GUIDANCE / NOT VERIFIED VULNERABILITIES',
                 bg='#101918', fg='#a3ff12', font=(mono, 10, 'bold'), anchor='w').pack(fill='x')
        tk.Label(self, textvariable=self.summary, bg='#101918', fg='#e8fff5',
                 font=(mono, 10), anchor='w', wraplength=900, justify='left').pack(fill='x', pady=(6, 4))
        body = ttk.Panedwindow(self, orient='horizontal')
        body.pack(fill='both', expand=True)
        left = tk.Frame(body, bg='#101918')
        right = tk.Frame(body, bg='#080f0e')
        body.add(left, weight=2)
        body.add(right, weight=3)
        self.chart = tk.Canvas(left, height=68, width=400, bg='#101918', highlightthickness=0)
        self.chart.pack(fill='x')
        table_frame = tk.Frame(left, bg='#101918')
        table_frame.pack(fill='both', expand=True)
        self.table = ttk.Treeview(table_frame, columns=('port', 'priority', 'service'), show='headings', height=2, style='Review.Treeview')
        for name, title, width in [('port', 'PORT', 55), ('priority', 'REVIEW TASK', 150), ('service', 'SERVICE GUESS', 170)]:
            self.table.heading(name, text=title)
            self.table.column(name, width=width, minwidth=45, anchor='w')
        self.table.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        scrollbar.pack(side='right', fill='y')
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.bind('<<TreeviewSelect>>', self.select)
        self.detail = tk.Text(right, height=6, width=50, wrap='word', bg='#080f0e', fg='#e8fff5',
                              font=(mono, 10), padx=12, pady=10, relief='flat', insertbackground='#a3ff12')
        detail_scroll = ttk.Scrollbar(right, orient='vertical', command=self.detail.yview)
        detail_scroll.pack(side='right', fill='y')
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.pack(fill='both', expand=True)
        self.write('Select a result to inspect evidence, conditional concerns, recommended actions and source links.\nNo banners, logins, exploitation or firewall changes are performed.')
        self.refresh([], 'No results yet')

    def write(self, text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def refresh(self, items, status):
        selected = self.table.selection()
        self.items = {str(item['port']): item for item in items}
        self.table.delete(*self.table.get_children())
        for key, item in self.items.items():
            self.table.insert('', 'end', iid=key, values=(key, item['review_priority'], item['service_inference']))
        self.summary.set(f'{len(items)} observed services | {status} | Vulnerabilities: NOT ASSESSED')
        self.chart.delete('all')
        for row, (name, color) in enumerate(COLORS.items()):
            count = sum(item['review_priority'] == name for item in items)
            y = row * 16 + 3
            self.chart.create_text(0, y+7, text=f'{name}: {count}', anchor='w', fill=color)
            self.chart.create_rectangle(200, y, 200 + 180 * count / max(1, len(items)), y+10, fill=color, outline='')
        if selected and selected[0] in self.items:
            self.table.selection_set(selected[0])
        else:
            self.write('Select a result for evidence and recommendations.\nReview tasks are conditional guidance, not vulnerability severity. Empty or partial results do not establish safety.')

    def select(self, _event=None):
        selected = self.table.selection()
        if not selected or selected[0] not in self.items:
            return
        item = self.items[selected[0]]
        self.write('\n\n'.join(f'{name.upper().replace("_", " ")}: {value}' for name,value in item.items()))
