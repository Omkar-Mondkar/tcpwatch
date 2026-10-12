"""Tkinter GUI: live packet/record table, detail pane, pattern editor."""
import collections, csv, datetime, threading, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from reader import PcapStream
from decoder import decode, addr, printable
from patterns import Profile

BG, SURF, ALT, FG, MUTED, ACC, SEL = '#14161b', '#1b1e25', '#20242c', '#d7dae0', '#7d8590', '#4f8cff', '#2c3e5f'
BASE = [('n', '#', 70, 'e'), ('time', 'Time', 100, 'w'), ('src', 'Source', 170, 'w'),
        ('dst', 'Destination', 170, 'w'), ('proto', 'Proto', 62, 'w'), ('len', 'Len', 55, 'e')]
FONT = ('Segoe UI', 10)
MONO = ('Consolas', 10)


def apply_style(root):
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use('clam')
    s.configure('.', background=BG, foreground=FG, font=FONT, bordercolor=BG, focuscolor=BG)
    s.configure('TFrame', background=BG)
    s.configure('TLabel', background=BG, foreground=FG)
    s.configure('Muted.TLabel', foreground=MUTED)
    s.configure('TCheckbutton', background=BG, foreground=FG)
    s.map('TCheckbutton', background=[('active', BG)])
    s.configure('TButton', background=ALT, foreground=FG, padding=(12, 5), borderwidth=0, relief='flat')
    s.map('TButton', background=[('active', '#2d3340'), ('pressed', ACC)])
    s.configure('Accent.TButton', background=ACC, foreground='white')
    s.map('Accent.TButton', background=[('active', '#6aa0ff')])
    s.configure('TEntry', fieldbackground=SURF, foreground=FG, insertcolor=FG, padding=5, bordercolor=ALT)
    s.configure('TCombobox', fieldbackground=SURF, background=ALT, foreground=FG, arrowcolor=FG, padding=4)
    s.map('TCombobox', fieldbackground=[('readonly', SURF)], foreground=[('readonly', FG)])
    root.option_add('*TCombobox*Listbox.background', SURF)
    root.option_add('*TCombobox*Listbox.foreground', FG)
    root.option_add('*TCombobox*Listbox.selectBackground', ACC)
    s.configure('Treeview', background=SURF, fieldbackground=SURF, foreground=FG, rowheight=25, borderwidth=0)
    s.map('Treeview', background=[('selected', SEL)], foreground=[('selected', 'white')])
    s.configure('Treeview.Heading', background=ALT, foreground=MUTED, padding=(8, 6), relief='flat', font=(FONT[0], 9, 'bold'))
    s.map('Treeview.Heading', background=[('active', '#2d3340')])
    for o in ('Vertical', 'Horizontal'):
        s.configure(f'{o}.TScrollbar', background=ALT, troughcolor=BG, arrowcolor=MUTED, borderwidth=0)
    s.configure('TPanedwindow', background=BG)


class App:
    def __init__(self, root, source, store, follow, max_rows=500000):
        self.root, self.source, self.store, self.follow = root, source, store, follow
        self.max_rows, self.trimmed, self.stream = max_rows, 0, None
        self.inbox = collections.deque()  # unbounded, but the reader applies backpressure (nothing is dropped)
        self.packets = collections.deque(maxlen=max_rows or None)
        self.meta, self.rows, self.parsed, self.n = {}, 0, 0, 0
        self.paused, self.stop, self.msg = False, threading.Event(), ''
        self._pps, self._last, self._flt_job, self._last_iid = 0, (time.time(), 0), None, None
        root.title(f'tcpwatch - {source}')
        root.geometry('1280x780')
        root.minsize(900, 500)
        apply_style(root)
        self._build()
        self.rebuild()
        threading.Thread(target=self._capture, daemon=True).start()
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.bind('<Control-f>', lambda e: self.flt_entry.focus_set())
        self._tick()
        self._stats()

    # ---------- UI ----------
    def _build(self):
        bar = ttk.Frame(self.root, padding=(12, 10))
        bar.pack(fill='x')
        self.btn_pause = ttk.Button(bar, text='Pause', command=self.toggle_pause, width=8)
        self.btn_pause.pack(side='left')
        ttk.Button(bar, text='Clear', command=self.clear).pack(side='left', padx=6)
        ttk.Button(bar, text='Export CSV', command=self.export).pack(side='left')
        ttk.Label(bar, text='Pattern', style='Muted.TLabel').pack(side='left', padx=(18, 6))
        self.prof = ttk.Combobox(bar, state='readonly', width=18, values=list(self.store.profiles))
        self.prof.set(self.store.active)
        self.prof.bind('<<ComboboxSelected>>', self._switch_profile)
        self.prof.pack(side='left')
        ttk.Button(bar, text='Edit patterns...', style='Accent.TButton',
                   command=lambda: PatternDialog(self)).pack(side='left', padx=6)
        self.auto = tk.BooleanVar(value=True)
        self.unparsed = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text='Auto-scroll', variable=self.auto).pack(side='right')
        ttk.Checkbutton(bar, text='Show unparsed', variable=self.unparsed,
                        command=self.rebuild).pack(side='right', padx=10)
        self.flt = tk.StringVar()
        self.flt.trace_add('write', self._filter_changed)
        self.flt_entry = ttk.Entry(bar, textvariable=self.flt, width=26)
        self.flt_entry.pack(side='right', padx=(0, 6))
        ttk.Label(bar, text='Filter', style='Muted.TLabel').pack(side='right', padx=6)

        pw = ttk.PanedWindow(self.root, orient='vertical')
        pw.pack(fill='both', expand=True, padx=12)
        top = ttk.Frame(pw)
        self.tree = ttk.Treeview(top, show='headings', selectmode='browse')
        ys = ttk.Scrollbar(top, orient='vertical', command=self.tree.yview)
        xs = ttk.Scrollbar(top, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ys.grid(row=0, column=1, sticky='ns')
        xs.grid(row=1, column=0, sticky='ew')
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        self.tree.tag_configure('odd', background=SURF)
        self.tree.tag_configure('even', background=ALT)
        self.tree.tag_configure('raw', foreground=MUTED, background=SURF)
        self.tree.bind('<<TreeviewSelect>>', self._select)
        pw.add(top, weight=4)

        bot = ttk.Frame(pw)
        self.detail = tk.Text(bot, height=9, bg=SURF, fg=FG, bd=0, padx=12, pady=8, font=MONO,
                              insertbackground=FG, state='disabled', wrap='word',
                              selectbackground=SEL, highlightthickness=0)
        ds = ttk.Scrollbar(bot, command=self.detail.yview)
        self.detail.configure(yscrollcommand=ds.set)
        self.detail.pack(side='left', fill='both', expand=True)
        ds.pack(side='right', fill='y')
        self.detail.tag_configure('h', foreground=ACC, font=(MONO[0], 10, 'bold'))
        self.detail.tag_configure('k', foreground=MUTED)
        pw.add(bot, weight=1)

        st = ttk.Frame(self.root, padding=(12, 6))
        st.pack(fill='x')
        self.lbl_l = ttk.Label(st, style='Muted.TLabel')
        self.lbl_r = ttk.Label(st, style='Muted.TLabel')
        self.lbl_l.pack(side='left')
        self.lbl_r.pack(side='right')

    def _setup_columns(self):
        names = self.store.current().column_names()
        ids = [c[0] for c in BASE] + [f'd{i}' for i in range(len(names))]
        self.tree.configure(columns=ids, displaycolumns=ids)
        for cid, title, w, anc in BASE:
            self.tree.heading(cid, text=title, anchor=anc)
            self.tree.column(cid, width=w, minwidth=40, anchor=anc, stretch=False)
        for i, nm in enumerate(names):
            self.tree.heading(f'd{i}', text=nm, anchor='w')
            self.tree.column(f'd{i}', width=130, minwidth=50, anchor='w', stretch=(i == len(names) - 1))

    # ---------- capture ----------
    def _capture(self):
        try:
            self.stream = PcapStream(self.source, self.follow)
            for ts, link, data in self.stream.packets(self.stop):
                while len(self.inbox) > 50000 and not self.stop.is_set():
                    time.sleep(0.02)  # backpressure: the pcap file itself is the buffer, so nothing is lost
                d = decode(link, data)
                if d is None:
                    continue
                self.n += 1
                d.update(n=self.n, ts=ts, len=len(data))
                self.inbox.append(d)
            self.msg = 'Finished - end of file reached' if not self.stop.is_set() else 'Stopped'
        except Exception as e:  # noqa
            self.msg = f'Error: {e}'

    def _tick(self):
        if not self.paused and self.inbox:
            batch = []
            for _ in range(min(5000, max(600, len(self.inbox) // 8))):  # catch up faster on big backlogs
                try:
                    batch.append(self.inbox.popleft())
                except IndexError:
                    break
            self.packets.extend(batch)
            self._insert(batch)
            if self.max_rows and self.rows > self.max_rows:
                kids = self.tree.get_children()[:self.rows - self.max_rows]
                self.trimmed += len(kids)
                self.tree.delete(*kids)
                for k in kids:
                    self.meta.pop(k, None)
                self.rows -= len(kids)
            if self.auto.get() and self._last_iid:
                self.tree.see(self._last_iid)
        self.root.after(50, self._tick)

    def _stats(self):
        now, (t0, n0) = time.time(), self._last
        self._pps = int((self.n - n0) / max(now - t0, 1e-3))
        self._last = (now, self.n)
        s = self.stream
        if self.source == '-':
            live = 'Streaming stdin'
        else:
            live = 'Starting...' if not s else ('Live - following file' if s.waiting else 'Reading file from start...')
        state = self.msg or ('Paused' if self.paused else live)
        self.lbl_l.config(text=f'{state}   |   {self.store.current().name}')
        self.lbl_r.config(text=f'{self.n:,} packets   {self.parsed:,} records   {self.rows:,} rows   {self._pps}/s   queued {len(self.inbox):,}' + (f'   trimmed {self.trimmed:,}' if self.trimmed else ''))
        self.root.after(1000, self._stats)

    # ---------- rows ----------
    def _insert(self, pkts):
        p = self.store.current()
        n = len(p.column_names())
        q = self.flt.get().strip().lower()
        for pkt in pkts:
            recs = p.parse(pkt)
            t = datetime.datetime.fromtimestamp(pkt['ts']).strftime('%H:%M:%S.%f')[:-3]
            base = (pkt['n'], t, addr(pkt['src'], pkt['sport']), addr(pkt['dst'], pkt['dport']), pkt['proto'], pkt['len'])
            if recs:
                self.parsed += len(recs)
                rows = [(base + tuple((r + [''] * n)[:n]), r) for r in recs]
            elif self.unparsed.get() and pkt['payload']:
                prev = printable(pkt['payload'][:120], nl=False)
                rows = [(base + (prev,) + ('',) * (n - 1), None)]
            else:
                continue
            for vals, rec in rows:
                if q and q not in ' '.join(map(str, vals)).lower():
                    continue
                tag = 'raw' if rec is None else ('odd' if self.rows & 1 else 'even')
                iid = self.tree.insert('', 'end', values=vals, tags=(tag,))
                self.meta[iid] = (pkt, rec)
                self._last_iid = iid
                self.rows += 1

    def rebuild(self):
        self._setup_columns()
        self.tree.delete(*self.tree.get_children())
        self.meta.clear()
        self.rows = self.parsed = 0
        self._last_iid = None
        self._insert(list(self.packets))
        if self._last_iid and self.auto.get():
            self.tree.see(self._last_iid)

    def _filter_changed(self, *_):
        if self._flt_job:
            self.root.after_cancel(self._flt_job)
        self._flt_job = self.root.after(250, self.rebuild)

    def _select(self, _):
        sel = self.tree.selection()
        if not sel or sel[0] not in self.meta:
            return
        pkt, rec = self.meta[sel[0]]
        names = self.store.current().column_names()
        t = self.detail
        t.config(state='normal')
        t.delete('1.0', 'end')
        flags = f'  [{pkt["flags"]}]' if pkt['flags'] else ''
        t.insert('end', f'#{pkt["n"]}  {addr(pkt["src"], pkt["sport"])} -> {addr(pkt["dst"], pkt["dport"])}  {pkt["proto"]}{flags}  {pkt["len"]} bytes\n', 'h')
        if rec:
            t.insert('end', '\nParsed fields\n', 'h')
            for i, v in enumerate(rec):
                t.insert('end', f'{(names[i] if i < len(names) else f"extra{i + 1}"):<18}', 'k')
                t.insert('end', v + '\n')
        t.insert('end', '\nPayload\n', 'h')
        t.insert('end', printable(pkt['payload'][:4000]))
        t.config(state='disabled')

    # ---------- actions ----------
    def toggle_pause(self):
        self.paused = not self.paused
        self.btn_pause.config(text='Resume' if self.paused else 'Pause')

    def clear(self):
        self.inbox.clear()
        self.packets.clear()
        self.rebuild()

    def _switch_profile(self, _=None):
        self.store.active = self.prof.get()
        self.store.save()
        self.rebuild()

    def on_pattern_change(self):
        self.prof.config(values=list(self.store.profiles))
        self.prof.set(self.store.active)
        self.rebuild()

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not path:
            return
        cols = self.tree['columns']
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow([self.tree.heading(c)['text'] for c in cols])
            for iid in self.tree.get_children():
                w.writerow(self.tree.item(iid, 'values'))

    def close(self):
        self.stop.set()
        self.root.destroy()


class PatternDialog(tk.Toplevel):
    FIELDS = [('Delimiter  (use \\t for tab)', 'delimiter'), ('Field names  (comma separated)', 'fields'),
              ('Record regex  (optional, group 1 = record)', 'regex'), ('Port  (0 = any)', 'port'),
              ('Min fields per record', 'minf')]

    def __init__(self, app):
        super().__init__(app.root)
        self.app, self.store, self.cur = app, app.store, app.store.active
        self.title('Data patterns')
        self.configure(bg=BG, padx=18, pady=16)
        self.transient(app.root)
        self.var = {k: tk.StringVar() for _, k in self.FIELDS + [('', 'proto')]}
        self.strip = tk.BooleanVar()
        top = ttk.Frame(self)
        top.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 12))
        self.combo = ttk.Combobox(top, state='readonly', width=26)
        self.combo.pack(side='left')
        self.combo.bind('<<ComboboxSelected>>', self._switch)
        ttk.Button(top, text='New', command=self._new).pack(side='left', padx=6)
        ttk.Button(top, text='Delete', command=self._delete).pack(side='left')
        r = 1
        for label, key in self.FIELDS:
            ttk.Label(self, text=label, style='Muted.TLabel').grid(row=r, column=0, sticky='w', pady=4, padx=(0, 14))
            ttk.Entry(self, textvariable=self.var[key], width=40).grid(row=r, column=1, sticky='ew', pady=4)
            r += 1
        ttk.Label(self, text='Protocol', style='Muted.TLabel').grid(row=r, column=0, sticky='w', pady=4)
        ttk.Combobox(self, textvariable=self.var['proto'], values=['any', 'tcp', 'udp'],
                     state='readonly', width=10).grid(row=r, column=1, sticky='w', pady=4)
        ttk.Checkbutton(self, text='Trim whitespace around fields', variable=self.strip).grid(
            row=r + 1, column=1, sticky='w', pady=4)
        ttk.Label(self, text='Test sample (live preview)', style='Muted.TLabel').grid(
            row=r + 2, column=0, columnspan=2, sticky='w', pady=(12, 4))
        self.sample = tk.Text(self, height=4, width=60, bg=SURF, fg=FG, bd=0, padx=8, pady=6, font=MONO,
                              insertbackground=FG, highlightthickness=0)
        self.sample.insert('1.0', '1001|alice|LOGIN|42.50|ok\n1002|bob|BUY|7.00|fail')
        self.sample.grid(row=r + 3, column=0, columnspan=2, sticky='ew')
        self.sample.bind('<KeyRelease>', lambda e: self._preview())
        self.out = tk.Text(self, height=5, width=60, bg=ALT, fg=FG, bd=0, padx=8, pady=6, font=MONO,
                           highlightthickness=0, state='disabled')
        self.out.grid(row=r + 4, column=0, columnspan=2, sticky='ew', pady=(8, 0))
        btns = ttk.Frame(self)
        btns.grid(row=r + 5, column=0, columnspan=2, sticky='e', pady=(14, 0))
        ttk.Button(btns, text='Cancel', command=self.destroy).pack(side='left', padx=6)
        ttk.Button(btns, text='Save & apply', style='Accent.TButton', command=self._apply).pack(side='left')
        self.columnconfigure(1, weight=1)
        self._refresh()
        self._load()
        for v in list(self.var.values()) + [self.strip]:
            v.trace_add('write', lambda *_: self._preview())
        self._preview()

    def _refresh(self):
        self.combo.config(values=list(self.store.profiles))
        self.combo.set(self.cur)

    def _load(self):
        p = self.store.profiles[self.cur]
        v = self.var
        v['delimiter'].set(p.delimiter)
        v['fields'].set(', '.join(p.fields))
        v['regex'].set(p.record_regex)
        v['proto'].set(p.proto)
        v['port'].set(str(p.port))
        v['minf'].set(str(p.min_fields))
        self.strip.set(p.strip)

    def _collect(self):
        v = self.var

        def num(s, d):
            try:
                return int(s.get())
            except ValueError:
                return d
        return Profile(self.cur, delimiter=v['delimiter'].get(),
                       fields=[f.strip() for f in v['fields'].get().split(',') if f.strip()],
                       record_regex=v['regex'].get(), proto=v['proto'].get() or 'any',
                       port=num(v['port'], 0), min_fields=num(v['minf'], 1), strip=self.strip.get())

    def _commit(self):
        self.store.profiles[self.cur] = self._collect()

    def _switch(self, _=None):
        self._commit()
        self.cur = self.combo.get()
        self._load()

    def _new(self):
        name = simpledialog.askstring('New pattern', 'Profile name:', parent=self)
        if name and name not in self.store.profiles:
            self._commit()
            self.store.profiles[name] = Profile(name)
            self.cur = name
            self._refresh()
            self._load()

    def _delete(self):
        if len(self.store.profiles) > 1:
            del self.store.profiles[self.cur]
            self.cur = next(iter(self.store.profiles))
            self._refresh()
            self._load()

    def _preview(self):
        p = self._collect()
        lines = [p.error] if p.error else []
        if not p.error:
            names = p.column_names()
            for i, rec in enumerate(p.parse_text(self.sample.get('1.0', 'end-1c')), 1):
                lines.append(f'{i}: ' + '  '.join(f'{names[j] if j < len(names) else "+"}={x}' for j, x in enumerate(rec)))
            if not lines:
                lines = ['(no records match)']
        self.out.config(state='normal')
        self.out.delete('1.0', 'end')
        self.out.insert('end', '\n'.join(lines))
        self.out.config(state='disabled')

    def _apply(self):
        p = self._collect()
        if p.error:
            messagebox.showerror('Invalid pattern', p.error, parent=self)
            return
        self._commit()
        self.store.active = self.cur
        self.store.save()
        self.app.on_pattern_change()
        self.destroy()
