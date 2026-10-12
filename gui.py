"""Live GUI: tkinter treeview with streaming updates, search, and pattern editor."""
import csv, datetime, queue, sys, threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from reader import PcapStream, PcapError
from decoder import decode, addr, printable
from patterns import Profile, clean_str

BG = '#1e1e24'
SURF = '#282830'
ALT = '#22222a'
FG = '#e4e4e8'
MUTED = '#888894'
ACC = '#4e9a06'
HDR_BG = '#18181e'
SEL_BG = '#3a3a46'
MONO = ('Consolas', 10) if sys.platform.startswith('win') else ('DejaVu Sans Mono', 10)
FONT = ('Segoe UI', 10) if sys.platform.startswith('win') else ('TkDefaultFont', 10)

BASE = [
    ('#', '#', 50, 'e'),
    ('time', 'Time', 110, 'w'),
    ('src', 'Source', 140, 'w'),
    ('dst', 'Destination', 140, 'w'),
    ('proto', 'Proto', 60, 'c'),
    ('len', 'Len', 50, 'e'),
]


class App:
    def __init__(self, root, source, store, follow=True, max_rows=500000):
        self.root, self.source, self.store = root, source, store
        self.follow, self.max_rows = follow, max_rows
        self.paused = False
        self.rows = 0
        self.meta = {}      # iid -> (pkt_dict, parsed_record_or_None, vals_tuple)
        self.inbox = queue.Queue(maxsize=10000)
        self.packets = []
        self.stop = threading.Event()
        self._last_iid = None
        self._autoscroll = True
        self._ncols = 0

        root.title(f'tcpwatch - {source}')
        root.geometry('1200x720')
        root.configure(bg=BG)
        self._style()
        self._layout()
        self._setup_columns()
        self._capture()
        self.root.after(50, self._poll)
        self.root.protocol('WM_DELETE_WINDOW', self.close)

    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use('clam')
        except Exception:
            pass
        s.configure('.', background=BG, foreground=FG, font=FONT)
        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=FG)
        s.configure('Muted.TLabel', background=BG, foreground=MUTED)
        s.configure('TButton', background=SURF, foreground=FG, borderwidth=0, padding=6)
        s.map('TButton', background=[('active', SEL_BG), ('pressed', HDR_BG)])
        s.configure('TCheckbutton', background=BG, foreground=FG)
        s.configure('TCombobox', fieldbackground=SURF, background=SURF, foreground=FG, borderwidth=0)
        s.configure('TEntry', fieldbackground=SURF, foreground=FG, borderwidth=0, insertcolor=FG)
        s.configure('Treeview', background=BG, fieldbackground=BG, foreground=FG, rowheight=22, font=MONO, borderwidth=0)
        s.configure('Treeview.Heading', background=HDR_BG, foreground=MUTED, relief='flat', font=FONT)
        s.map('Treeview.Heading', background=[('active', SURF)])
        s.map('Treeview', background=[('selected', SEL_BG)], foreground=[('selected', FG)])

    def _layout(self):
        # Toolbar
        tb = ttk.Frame(self.root, padding=(10, 8))
        tb.pack(fill='x')

        ttk.Label(tb, text='Pattern:').pack(side='left', padx=(0, 4))
        self.prof = ttk.Combobox(tb, values=list(self.store.profiles), state='readonly', width=18)
        self.prof.set(self.store.active)
        self.prof.pack(side='left', padx=(0, 6))
        self.prof.bind('<<ComboboxSelected>>', self._switch_profile)

        ttk.Button(tb, text='Edit patterns...', command=lambda: PatternDialog(self)).pack(side='left', padx=(0, 10))

        ttk.Label(tb, text='Filter:').pack(side='left', padx=(0, 4))
        self.flt = ttk.Entry(tb, width=22)
        self.flt.pack(side='left', padx=(0, 10))
        self.flt.bind('<KeyRelease>', lambda e: self.rebuild())

        self.unparsed = tk.BooleanVar(value=False)
        ttk.Checkbutton(tb, text='Show unparsed', variable=self.unparsed,
                        command=self.rebuild).pack(side='left', padx=(0, 10))

        self.btn_pause = ttk.Button(tb, text='Pause', command=self.toggle_pause)
        self.btn_pause.pack(side='left', padx=(0, 6))
        ttk.Button(tb, text='Clear', command=self.clear).pack(side='left', padx=(0, 6))
        ttk.Button(tb, text='Export CSV', command=self.export).pack(side='left')

        # Split pane (Tree on top, Details on bottom)
        paned = ttk.PanedWindow(self.root, orient='vertical')
        paned.pack(fill='both', expand=True, padx=8, pady=(0, 4))

        # Top: Table + Scrollbar
        top = ttk.Frame(paned)
        paned.add(top, weight=3)

        self.tree = ttk.Treeview(top, selectmode='browse', show='headings')
        vs = ttk.Scrollbar(top, orient='vertical', command=self.tree.yview)
        hs = ttk.Scrollbar(top, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=self._on_vscroll(vs), xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vs.grid(row=0, column=1, sticky='ns')
        hs.grid(row=1, column=0, sticky='ew')
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)

        self.tree.tag_configure('odd', background=ALT)
        self.tree.tag_configure('even', background=BG)
        self.tree.tag_configure('raw', foreground=MUTED)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)

        # Bottom: Detail text
        bot = ttk.Frame(paned)
        paned.add(bot, weight=1)

        self.detail = tk.Text(bot, height=6, bg=SURF, fg=FG, bd=0, padx=10, pady=8, font=MONO,
                              insertbackground=FG, selectbackground=SEL_BG, highlightthickness=0)
        vs2 = ttk.Scrollbar(bot, orient='vertical', command=self.detail.yview)
        self.detail.configure(yscrollcommand=vs2.set, state='disabled')
        self.detail.pack(side='left', fill='both', expand=True)
        vs2.pack(side='right', fill='y')
        self.detail.tag_configure('h', foreground=MUTED, font=FONT)
        self.detail.tag_configure('k', foreground='#729fcf')

        # Status bar
        sb = ttk.Frame(self.root, padding=(10, 4))
        sb.pack(fill='x')
        self.lbl_l = ttk.Label(sb, text='Starting...', style='Muted.TLabel')
        self.lbl_r = ttk.Label(sb, text='', style='Muted.TLabel')
        self.lbl_l.pack(side='left')
        self.lbl_r.pack(side='right')

    def _setup_columns(self, keep=False):
        names = self.store.current().column_names()
        ids = [c[0] for c in BASE] + [f'd{i}' for i in range(len(names))]
        old = {c: self.tree.column(c, 'width') for c in self.tree['columns']} if keep else {}
        self.tree.configure(columns=ids, displaycolumns=ids)
        for cid, title, w, anc in BASE:
            self.tree.heading(cid, text=title, anchor=anc)
            self.tree.column(cid, width=old.get(cid, w), minwidth=40, anchor=anc, stretch=False)
        for i, nm in enumerate(names):
            self.tree.heading(f'd{i}', text=nm, anchor='w')
            self.tree.column(f'd{i}', width=old.get(f'd{i}', 130), minwidth=50, anchor='w',
                             stretch=(i == len(names) - 1))
        self._ncols = len(names)

    def _capture(self):
        try:
            self.stream = PcapStream(self.source, self.follow)
        except PcapError as e:
            messagebox.showerror('Capture error', str(e))
            self.root.destroy()
            return
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def _worker(self):
        n = 0
        buf = []
        try:
            for ts, link, data in self.stream.packets(self.stop):
                d = decode(link, data)
                if d is None:
                    continue
                n += 1
                pkt = {'n': n, 'ts': ts, 'len': len(data), **d}
                buf.append(pkt)
                if len(buf) >= 100:
                    self.inbox.put(buf)
                    buf = []
            if buf:
                self.inbox.put(buf)
        except PcapError as e:
            self.inbox.put(('err', str(e)))
        finally:
            self.inbox.put(('done', None))

    def _on_vscroll(self, scrollbar):
        def cb(first, last):
            scrollbar.set(first, last)
            self._autoscroll = (float(last) >= 0.99)
        return cb

    def _poll(self):
        batch = []
        while not self.inbox.empty() and len(batch) < 1000:
            item = self.inbox.get()
            if isinstance(item, tuple) and item[0] in ('err', 'done'):
                kind, msg = item
                if kind == 'err':
                    messagebox.showerror('tcpwatch', msg)
                self.lbl_l.config(text='Capture finished (end of file)' if not self.follow else 'Idle')
                return
            batch.extend(item)
        if batch and not self.paused:
            self.packets.extend(batch)
            if self.max_rows and len(self.packets) > self.max_rows:
                del self.packets[:-self.max_rows]
            self._insert(batch)
        s = f'{len(self.packets):,} packets  |  {self.rows:,} rows'
        if self.paused:
            s += '  [PAUSED]'
        self.lbl_l.config(text=s)
        self.lbl_r.config(text=self.source)
        self.root.after(30, self._poll)

    def _insert(self, pkts):
        p = self.store.current()
        q = self.flt.get().strip().lower()
        for pkt in pkts:
            recs = p.parse(pkt)
            if p.dynamic and p.ncols != self._ncols:   # a new key appeared -> grow the table
                self._setup_columns(keep=True)
            n = self._ncols
            t = datetime.datetime.fromtimestamp(pkt['ts']).strftime('%H:%M:%S.%f')[:-3]
            base = (pkt['n'], t, addr(pkt['src'], pkt['sport']), addr(pkt['dst'], pkt['dport']), pkt['proto'], pkt['len'])
            if recs:
                rows = [(base + tuple((r + [''] * n)[:n]), r) for r in recs]
            elif self.unparsed.get() and pkt['payload']:
                prev = printable(pkt['payload'][:120], nl=False)
                rows = [(base + ((prev,) + ('',) * (n - 1) if n else ()), None)]
            else:
                continue
            for vals, rec in rows:
                if q and q not in ' '.join(map(str, vals)).lower():
                    continue
                tag = 'raw' if rec is None else ('odd' if self.rows & 1 else 'even')
                iid = self.tree.insert('', 'end', values=vals, tags=(tag,))
                self.meta[iid] = (pkt, rec, vals)
                self._last_iid = iid
                self.rows += 1

        if self._autoscroll and self._last_iid:
            self.tree.see(self._last_iid)

    def rebuild(self):
        self.rows = 0
        self.meta.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._setup_columns()
        self._insert(self.packets)

    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel or sel[0] not in self.meta:
            return
        pkt, rec, _v = self.meta[sel[0]]
        p = self.store.current()
        names = p.column_names()
        t = self.detail
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', 'Packet details\n', 'h')
        for k in ('n', 'time', 'src', 'sport', 'dst', 'dport', 'proto', 'len', 'flags'):
            if k in pkt and pkt[k]:
                t.insert('end', f'{k:<18}', 'k')
                t.insert('end', f'{pkt[k]}\n')
        if rec:
            t.insert('end', '\nParsed fields\n', 'h')
            for i, v in enumerate(rec):
                if p.dynamic and v == '':      # key/value rows only carry some of the columns
                    continue
                t.insert('end', f'{(names[i] if i < len(names) else f"extra{i + 1}"):<18}', 'k')
                t.insert('end', str(v) + '\n')
        t.insert('end', '\nPayload\n', 'h')
        t.insert('end', printable(pkt['payload'][:4000]))
        t.config(state='disabled')

    def toggle_pause(self):
        self.paused = not self.paused
        self.btn_pause.config(text='Resume' if self.paused else 'Pause')

    def clear(self):
        self.inbox.clear()
        self.packets.clear()
        self.store.current().reset()
        self.rebuild()

    def _switch_profile(self, _=None):
        self.store.active = self.prof.get()
        self.store.save()
        self.store.current().reset()
        self.rebuild()

    def on_pattern_change(self):
        self.prof.config(values=list(self.store.profiles))
        self.prof.set(self.store.active)
        self.store.current().reset()
        self.rebuild()

    def export(self):
        fn = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv'), ('All', '*.*')])
        if not fn:
            return
        cols = list(self.tree['displaycolumns'])
        with open(fn, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow([self.tree.heading(c)['text'] for c in cols])
            for iid in self.tree.get_children():
                row = list(self.meta[iid][2])
                w.writerow(row + [''] * (len(cols) - len(row)))

    def close(self):
        self.stop.set()
        self.root.destroy()


class PatternDialog(tk.Toplevel):
    FIELDS = [
        ('Delimiter', 'delimiter'),
        ('Field names  (comma separated)', 'fields'),
        ('Record regex (group 1 = record)', 'regex'),
        ('Port (0 = any)', 'port'),
        ('Min fields per record', 'minf'),
    ]

    def __init__(self, app):
        super().__init__(app.root)
        self.app, self.store = app, app.store
        self.cur = self.store.active
        self.title('Data patterns')
        self.configure(bg=BG, padx=18, pady=16)
        self.transient(app.root)
        self.var = {k: tk.StringVar() for _, k in self.FIELDS + [('', 'proto'), ('', 'mode')]}
        self.lbl = {}
        self.strip = tk.BooleanVar()
        top = ttk.Frame(self)
        top.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 12))
        self.combo = ttk.Combobox(top, values=list(self.store.profiles), state='readonly', width=26)
        self.combo.pack(side='left')
        self.combo.bind('<<ComboboxSelected>>', self._switch)
        ttk.Button(top, text='New', command=self._new).pack(side='left', padx=6)
        ttk.Button(top, text='Delete', command=self._delete).pack(side='left')
        ttk.Label(self, text='Mode', style='Muted.TLabel').grid(row=1, column=0, sticky='w', pady=4)
        ttk.Combobox(self, textvariable=self.var['mode'], values=['positional', 'keyvalue'],
                     state='readonly', width=14).grid(row=1, column=1, sticky='w', pady=4)
        r = 2
        for label, key in self.FIELDS:
            self.lbl[key] = ttk.Label(self, text=label, style='Muted.TLabel')
            self.lbl[key].grid(row=r, column=0, sticky='w', pady=4, padx=(0, 14))
            ttk.Entry(self, textvariable=self.var[key], width=40).grid(row=r, column=1, sticky='ew', pady=4)
            r += 1
        ttk.Label(self, text='Protocol', style='Muted.TLabel').grid(row=r, column=0, sticky='w', pady=4)
        ttk.Combobox(self, textvariable=self.var['proto'], values=['any', 'tcp', 'udp'], state='readonly',
                     width=10).grid(row=r, column=1, sticky='w', pady=4)
        ttk.Checkbutton(self, text='Strip whitespace & control characters', variable=self.strip).grid(
            row=r + 1, column=1, sticky='w', pady=4)

        ttk.Label(self, text='Live preview (edit pattern or sample text to test):', style='Muted.TLabel').grid(
            row=r + 2, column=0, columnspan=2, sticky='w', pady=(12, 4))
        self.sample = tk.Text(self, height=4, width=60, bg=SURF, fg=FG, bd=0, padx=8, pady=6, font=MONO,
                              insertbackground=FG, highlightthickness=0)
        self.sample.insert('1.0', 'DEBUG|15:35:27.803275|LTP_MSG1|Ex|12|SN|51833032|Token| 44592|LTP|  16265|OpenInterest|11047205|FeedTimestamp|179138714354384\nINFO|15:35:27.9|DEPTH_MSG2|Ex|12|Token|44592|Bid|16260|Ask|16265')
        self.sample.grid(row=r + 3, column=0, columnspan=2, sticky='ew')
        self.sample.bind('<KeyRelease>', lambda e: self._preview())
        self.out = tk.Text(self, height=5, width=60, bg=ALT, fg=FG, bd=0, padx=8, pady=6, font=MONO,
                           state='disabled', highlightthickness=0)
        self.out.grid(row=r + 4, column=0, columnspan=2, sticky='ew', pady=(4, 12))

        btn = ttk.Frame(self)
        btn.grid(row=r + 5, column=0, columnspan=2, sticky='e')
        ttk.Button(btn, text='Save & Apply', command=self._save).pack(side='right', padx=(6, 0))
        ttk.Button(btn, text='Cancel', command=self.destroy).pack(side='right')

        for v in self.var.values():
            v.trace_add('write', lambda *_: self._preview())
        self.strip.trace_add('write', lambda *_: self._preview())
        self._load()

    def _load(self):
        p = self.store.profiles[self.cur]
        v = self.var
        v['mode'].set(p.mode)
        v['delimiter'].set(p.delimiter)
        v['fields'].set(', '.join(p.fields))
        v['regex'].set(p.record_regex)
        v['proto'].set(p.proto)
        v['port'].set(str(p.port or ''))
        v['minf'].set(str(p.min_fields))
        self.strip.set(p.strip)
        self.combo.set(self.cur)
        self._preview()

    def _collect(self):
        v = self.var
        def num(s, d):
            try:
                return int(s.get())
            except ValueError:
                return d
        return Profile(self.cur, mode=v['mode'].get() or 'positional', delimiter=v['delimiter'].get(),
                       fields=[f.strip() for f in v['fields'].get().split(',') if f.strip()],
                       record_regex=v['regex'].get(), proto=v['proto'].get() or 'any',
                       port=num(v['port'], 0), min_fields=num(v['minf'], 1), strip=self.strip.get())

    def _switch(self, _=None):
        self.cur = self.combo.get()
        self._load()

    def _new(self):
        name = f'Profile {len(self.store.profiles) + 1}'
        self.store.profiles[name] = Profile(name)
        self.cur = name
        self.combo.config(values=list(self.store.profiles))
        self._load()

    def _delete(self):
        if len(self.store.profiles) <= 1:
            messagebox.showwarning('Cannot delete', 'Keep at least one pattern profile.')
            return
        del self.store.profiles[self.cur]
        self.cur = next(iter(self.store.profiles))
        self.combo.config(values=list(self.store.profiles))
        self._load()

    def _preview(self):
        p = self._collect()
        kv = p.dynamic
        if 'fields' in self.lbl:
            self.lbl['fields'].config(text='Leading field names (before key|value pairs)' if kv
                                      else 'Field names  (comma separated)')
        lines = [p.error] if p.error else []
        if not p.error:
            for i, rec in enumerate(p.parse_text(self.sample.get('1.0', 'end-1c')), 1):
                names = p.column_names()
                lines.append(f'{i}: ' + '  '.join(f'{names[j] if j < len(names) else "+"}={x}'
                                                  for j, x in enumerate(rec) if not (kv and x == '')))
            if not lines:
                lines = ['(no records match)']
        self.out.config(state='normal')
        self.out.delete('1.0', 'end')
        self.out.insert('end', '\n'.join(lines))
        self.out.config(state='disabled')

    def _save(self):
        p = self._collect()
        if p.error:
            messagebox.showerror('Pattern error', p.error)
            return
        self.store.profiles[self.cur] = p
        self.store.active = self.cur
        self.store.save()
        self.app.on_pattern_change()
        self.destroy()
