"""Configurable data patterns. A profile describes how to split a payload into records and fields.

Modes:
  positional : every field has a fixed position           a|b|c|d
  keyvalue   : N leading fields, then variable key|value pairs   DEBUG|15:35:27|MSG|Ex|12|SN|5|LTP|99
               (columns are the leading field names + every key seen so far, added dynamically)
"""
import json, re

DEFAULTS = {'mode': 'positional', 'delimiter': '|', 'fields': [], 'record_regex': '', 'proto': 'any',
            'port': 0, 'min_fields': 2, 'strip': True}

ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd\r]')


def clean_str(s):
    """Strip ANSI escape codes, null bytes, non-printable control chars, and whitespace."""
    if not s:
        return ''
    if isinstance(s, (bytes, bytearray)):
        s = s.decode('utf-8', 'replace')
    s = ANSI_RE.sub('', str(s))
    s = CONTROL_RE.sub('', s)
    s = s.replace('\ufeff', '').replace('\u200b', '')
    return s.strip()


class Profile:
    def __init__(self, name, **kw):
        self.name = name
        d = dict(DEFAULTS)
        d.update({k: v for k, v in kw.items() if k in DEFAULTS})
        self.__dict__.update(d)
        if self.mode == 'kv':
            self.mode = 'keyvalue'
        if self.mode not in ('positional', 'keyvalue'):
            self.mode = 'positional'
        self.keys, self._keyset = [], set()   # keys discovered so far (keyvalue mode); append-only
        self.error, self._rx = '', None
        if self.record_regex:
            try:
                self._rx = re.compile(self.record_regex, re.M)
            except re.error as e:
                self.error = f'Regex error: {e}'

    def to_dict(self):
        return {k: getattr(self, k) for k in DEFAULTS}

    @property
    def dynamic(self):
        return self.mode == 'keyvalue'

    def reset(self):
        self.keys.clear()
        self._keyset.clear()

    def column_names(self):
        if self.dynamic:
            return list(self.fields) + self.keys
        return list(self.fields) or [f'F{i}' for i in range(1, 9)]

    @property
    def ncols(self):
        return len(self.fields) + len(self.keys) if self.dynamic else len(self.column_names())

    def matches(self, pkt):
        if self.proto != 'any' and pkt['proto'].lower() != self.proto:
            return False
        return not self.port or self.port in (pkt['sport'], pkt['dport'])

    def _split(self, text):
        text = ANSI_RE.sub('', text)
        if not text:
            return
        if self._rx:
            recs = [(m.group(1) or '') if m.re.groups else m.group(0) for m in self._rx.finditer(text)]
        else:
            recs = text.splitlines() or [text]
        delim = self.delimiter.replace('\\t', '\t')
        for r in recs:
            if not delim:
                continue
            r = r.strip('\x00\r\n ')
            if not r:
                continue
            parts = r.split(delim)
            if self.strip:
                parts = [clean_str(p) for p in parts]
            else:
                parts = [CONTROL_RE.sub('', p) for p in parts]
            while parts and parts[-1] == '':
                parts.pop()
            if len(parts) >= self.min_fields:
                yield parts

    def _parse_kv(self, rest):
        """Parse variable payload body into clean key-value pairs."""
        kv = {}
        if not rest:
            return kv

        # Unpack tokens if any item has control separators (SOH, RS, US, NUL) or sub-delimiters
        items = []
        for r in rest:
            if not r:
                continue
            if any(c in r for c in ('\x01', '\x1e', '\x1f', '\x00')):
                sub = re.split(r'[\x01\x1e\x1f\x00]+', r)
                items.extend(p for p in sub if p)
            elif len(rest) == 1 and (',' in r or ';' in r) and ('=' in r or ':' in r):
                sub = re.split(r'[,;]+', r)
                items.extend(p for p in sub if p)
            else:
                items.append(r)

        eq_count = sum(1 for x in items if '=' in x)
        colon_count = sum(1 for x in items if ':' in x) if not eq_count else 0

        if eq_count > 0:
            for item in items:
                item = clean_str(item)
                if not item:
                    continue
                k, v = item.split('=', 1) if '=' in item else (item, '')
                k, v = clean_str(k), clean_str(v)
                if not k:
                    continue
                key, j = k, 2
                while key in kv:
                    key, j = f'{k}#{j}', j + 1
                kv[key] = v
        elif colon_count > 0 and colon_count >= len(items) // 2:
            for item in items:
                item = clean_str(item)
                if not item:
                    continue
                k, v = item.split(':', 1) if ':' in item else (item, '')
                k, v = clean_str(k), clean_str(v)
                if not k:
                    continue
                key, j = k, 2
                while key in kv:
                    key, j = f'{k}#{j}', j + 1
                kv[key] = v
        else:
            for i in range(0, len(items), 2):
                k = clean_str(items[i])
                v = clean_str(items[i + 1]) if i + 1 < len(items) else ''
                if not k and not v:
                    continue
                if not k:
                    continue
                key, j = k, 2
                while key in kv:
                    key, j = f'{k}#{j}', j + 1
                kv[key] = v
        return kv

    def raw_text(self, text):
        """positional -> [list of str];  keyvalue -> [(lead_values, {key: value})]"""
        out = []
        for parts in self._split(text):
            if not self.dynamic:
                out.append(parts)
                continue
            n = len(self.fields)
            lead = [clean_str(x) for x in parts[:n]]
            rest = parts[n:]
            kv = self._parse_kv(rest)
            out.append((lead, kv))
        return out

    def parse_raw(self, pkt):
        if not pkt['payload'] or not self.matches(pkt):
            return []
        return self.raw_text(pkt['payload'].decode('utf-8', 'replace'))

    def parse_text(self, text):
        """Records as lists aligned with column_names() (keyvalue mode registers new keys as columns)."""
        raw = self.raw_text(text)
        if not self.dynamic:
            return raw
        for _lead, kv in raw:
            for k in kv:
                if k not in self._keyset:
                    self._keyset.add(k)
                    self.keys.append(k)
        n = len(self.fields)
        return [lead + [''] * max(0, n - len(lead)) + [kv.get(k, '') for k in self.keys] for lead, kv in raw]

    def parse(self, pkt):
        if not pkt['payload'] or not self.matches(pkt):
            return []
        return self.parse_text(pkt['payload'].decode('utf-8', 'replace'))


class PatternStore:
    def __init__(self, path):
        self.path, self.profiles, self.active = path, {}, ''
        try:
            with open(path, encoding='utf-8') as f:
                cfg = json.load(f)
            for name, d in cfg.get('profiles', {}).items():
                self.profiles[name] = Profile(name, **d)
            self.active = cfg.get('active', '')
        except (OSError, ValueError):
            pass
        if not self.profiles:
            self.profiles['Key-value log (Level|Time|Msg|k|v|k|v...)'] = Profile(
                'Key-value log (Level|Time|Msg|k|v|k|v...)',
                mode='keyvalue',
                fields=['Level', 'Time', 'Msg'],
                min_fields=2
            )
            self.profiles['Pipe (|) positional'] = Profile('Pipe (|) positional')
        if self.active not in self.profiles:
            self.active = next(iter(self.profiles))

    def current(self):
        return self.profiles[self.active]

    def save(self):
        cfg = {'active': self.active, 'profiles': {n: p.to_dict() for n, p in self.profiles.items()}}
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=2)
        except OSError:
            pass
