"""Terminal CLI mode: streaming table, csv, tsv, or json."""
import csv, datetime, json, os, signal, sys

from reader import PcapStream, PcapError
from decoder import decode, addr, printable
from patterns import Profile, clean_str

META = ['#', 'time', 'src', 'dst', 'proto', 'len']
META_W = [7, 23, 21, 21, 6, 5]


def build_profile(a, store):
    if a.profile:
        if a.profile not in store.profiles:
            sys.exit(f'unknown profile {a.profile!r}')
        store.active = a.profile
    base = store.current()
    ov = {}
    if getattr(a, 'mode', None):
        ov['mode'] = a.mode
    if a.delimiter is not None:
        ov['delimiter'] = a.delimiter
    if a.fields is not None:
        ov['fields'] = [f.strip() for f in a.fields.split(',') if f.strip()]
    if a.regex is not None:
        ov['record_regex'] = a.regex
    if a.proto is not None:
        ov['proto'] = a.proto
    if a.port is not None:
        ov['port'] = a.port
    if a.min_fields is not None:
        ov['min_fields'] = a.min_fields
    if not ov:
        return base
    d = base.to_dict()
    d.update(ov)
    p = Profile('cli_override', **d)
    if p.error:
        sys.exit(p.error)
    return p


def run(a, store):
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # `| head` exits quietly
    prof = build_profile(a, store)
    kv = prof.dynamic
    names = prof.column_names()
    nf = len(names)
    nlead = len(prof.fields)
    keycols = [k.strip() for k in a.keys.split(',') if k.strip()] if (getattr(a, 'keys', None) and kv) else []
    dcols = (list(prof.fields) + (keycols or ['data'])) if kv else names
    fmt = a.format
    out = open(a.output, 'w', encoding='utf-8', newline='') if a.output else sys.stdout
    tty = out.isatty()
    flush_each = a.pcap == '-' or tty
    stream = PcapStream(a.pcap, follow=not a.no_follow)
    stream.on_idle = out.flush  # flush as soon as we've caught up with the end of the file
    cols = ([] if a.no_meta else META) + dcols
    widths = ([] if a.no_meta else META_W) + [max(len(x), 12) for x in dcols]
    writer = csv.writer(out, delimiter=',' if fmt == 'csv' else '\t', lineterminator='\n')

    def line(row):
        return '  '.join(clean_str(str(x)).replace('\n', ' ').ljust(widths[i] if i < len(widths) else 0)
                         for i, x in enumerate(row)).rstrip()

    def make(rec):
        """-> (cell values, dict for json)"""
        if kv:
            lead, kvd = rec
            lead = [clean_str(x) for x in lead] + [''] * max(0, nlead - len(lead))
            tail = [clean_str(kvd.get(k, '')) for k in keycols] if keycols else [' '.join(f'{k}={v}' for k, v in kvd.items())]
            return lead + tail, {**dict(zip(prof.fields, lead)), **kvd}
        vals = [clean_str(x) for x in rec] + [''] * max(0, nf - len(rec))
        return vals, {(names[i] if i < nf else f'extra{i + 1 - nf}'): v for i, v in enumerate(vals)}

    if not a.no_header and fmt != 'json':
        if fmt == 'table':
            h = line(cols)
            out.write(h + '\n' + '-' * len(h) + '\n')
        else:
            writer.writerow(cols)

    grep = a.grep.lower() if a.grep else ''
    n = recs = 0
    try:
        for ts, link, data in stream.packets(stop=threading_event_stub()):
            d = decode(link, data)
            if d is None:
                continue
            n += 1
            parsed = prof.parse_raw(d)
            if parsed:
                rows = parsed
                recs += len(parsed)
            elif a.unparsed and d['payload']:
                pv = printable(d['payload'][:120], nl=False)
                rows = [([pv], {}) if kv else [pv]]
            else:
                continue
            t = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            meta = [n, t, addr(d['src'], d['sport']), addr(d['dst'], d['dport']), d['proto'], len(data)]
            for rec in rows:
                vals, jd = make(rec)
                row = vals if a.no_meta else meta + vals
                if grep and grep not in ' '.join(map(str, row)).lower():
                    continue
                if fmt == 'json':
                    obj = {} if a.no_meta else dict(zip(META, meta))
                    obj['data'] = jd
                    out.write(json.dumps(obj, ensure_ascii=False) + '\n')
                elif fmt == 'table':
                    out.write(line(row) + '\n')
                else:
                    writer.writerow(row)
                if flush_each:
                    out.flush()
                if a.count and recs >= a.count:
                    return 0
    except PcapError as e:
        sys.exit(f'tcpwatch: {e}')
    except KeyboardInterrupt:
        pass
    finally:
        if a.output:
            out.close()
    if not a.quiet:
        sys.stderr.write(f'\ntcpwatch: {n} packets read, {recs} records\n')
    return 0


def threading_event_stub():
    class E:
        def is_set(self):
            return False
    return E()
