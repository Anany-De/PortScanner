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
        self.chart = tk.Canvas(self, height=88, bg='#101918', highlightthickness=0)
        self.chart.pack(fill='x')
        self.table = ttk.Treeview(self, columns=('port', 'priority', 'service'), show='headings', height=4)
        for name, title, width in [('port', 'PORT', 85), ('priority', 'REVIEW TASK / CONDITIONAL', 260), ('service', 'INFERRED SERVICE / UNVERIFIED', 360)]:
            self.table.heading(name, text=title)
            self.table.column(name, width=width, anchor='w')
        table_frame = tk.Frame(self, bg='#101918')
        table_frame.pack(fill='both', expand=True)
        self.table.pack(in_=table_frame, side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        scrollbar.pack(side='right', fill='y')
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.bind('<<TreeviewSelect>>', self.select)
        self.detail = tk.Text(self, height=10, wrap='word', bg='#080f0e', fg='#e8fff5',
                              font=(mono, 10), padx=12, pady=10, relief='flat', insertbackground='#a3ff12')
        detail_scroll = ttk.Scrollbar(self, orient='vertical', command=self.detail.yview)
        detail_scroll.pack(side='right', fill='y', pady=(8,0))
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.pack(fill='both', expand=True, pady=(8, 0))
        self.write('Select a result to inspect evidence, conditional concerns, recommended actions and source links.\nNo banners, logins, exploitation or firewall changes are performed.')

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
            y = row * 21 + 4
            self.chart.create_text(0, y+7, text=f'{name}: {count}', anchor='w', fill=color)
            self.chart.create_rectangle(230, y, 230 + 400 * count / max(1, len(items)), y+12, fill=color, outline='')
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
