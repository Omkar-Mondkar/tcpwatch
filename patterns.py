"""Configurable data patterns. Each profile describes how to split a payload into records and fields."""
import json, re

DEFAULTS = {'delimiter': '|', 'fields': [], 'record_regex': '', 'proto': 'any',
            'port': 0, 'min_fields': 2, 'strip': True}


class Profile:
    def __init__(self, name, **kw):
        self.name = name
        d = dict(DEFAULTS)
        d.update({k: v for k, v in kw.items() if k in DEFAULTS})
        self.__dict__.update(d)
        self.error, self._rx = '', None
        if self.record_regex:
            try:
                self._rx = re.compile(self.record_regex, re.M)
            except re.error as e:
                self.error = f'Regex error: {e}'

    def to_dict(self):
        return {k: getattr(self, k) for k in DEFAULTS}

    def column_names(self):
        return list(self.fields) or [f'F{i}' for i in range(1, 9)]

    def matches(self, pkt):
        if self.proto != 'any' and pkt['proto'].lower() != self.proto:
            return False
        return not self.port or self.port in (pkt['sport'], pkt['dport'])

    def parse_text(self, text):
        """Return a list of records; each record is a list of field strings."""
        if self._rx:
            recs = [(m.group(1) or '') if m.re.groups else m.group(0) for m in self._rx.finditer(text)]
        else:
            recs = text.splitlines()
        delim = self.delimiter.replace('\\t', '\t')
        out = []
        for r in recs:
            if not delim:
                continue
            parts = r.split(delim)
            if self.strip:
                parts = [p.strip() for p in parts]
            if len(parts) >= self.min_fields:
                out.append(parts)
        return out

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
            self.profiles['Pipe (|)'] = Profile('Pipe (|)')
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
