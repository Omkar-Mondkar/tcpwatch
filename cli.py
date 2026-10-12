"""CLI mode: parse the pcap from the first record to the last, then (optionally) keep following new packets."""
import csv, datetime, json, os, signal, sys

from reader import PcapStream, PcapError
from decoder import decode, addr
from patterns import Profile

META = ['n', 'time', 'src', 'dst', 'proto', 'len']
META_W = [7, 23, 21, 21, 6, 5]


def build_profile(a, store):
    if a.profile:
        if a.profile not in store.profiles:
            raise SystemExit(f'unknown profile {a.profile!r}; available: {", ".join(store.profiles)}')
        store.active = a.profile
    base = store.current()
    ov = {}
    if a.delimiter is not None:
        ov['delimiter'] = a.delimiter
    if a.fields is not None:
        ov['fields'] = [f.strip() for f in a.fields.split(',') if f.strip()]
    if a.regex is not None:
        ov['record_regex'] = a.regex
    if a.proto:
        ov['proto'] = a.proto
    if a.port is not None:
        ov['port'] = a.port
    if a.min_fields is not None:
        ov['min_fields'] = a.min_fields
    prof = base
    if ov:  # ad-hoc profile = selected profile + command-line overrides (not saved)
        d = base.to_dict()
        d.update(ov)
        prof = Profile(base.name + '*', **d)
    if prof.error:
        raise SystemExit(prof.error)
    return prof


def run(a, store):
    if hasattr(signal, 'SIGPIPE'):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # `| head` exits quietly
    prof = build_profile(a, store)
    names = prof.column_names()
    nf = len(names)
    fmt = a.format
    out = open(a.output, 'w', encoding='utf-8', newline='') if a.output else sys.stdout
    tty = out.isatty()
    flush_each = a.pcap == '-' or tty
    stream = PcapStream(a.pcap, follow=not a.no_follow)
    stream.on_idle = out.flush  # flush as soon as we've caught up with the end of the file
    cols = ([] if a.no_meta else META) + names
    widths = ([] if a.no_meta else META_W) + [max(len(x), 12) for x in names]
    writer = csv.writer(out, delimiter=',' if fmt == 'csv' else '\t', lineterminator='\n')

    def line(row):
        return '  '.join(str(x).replace('\n', ' ').replace('\r', '').ljust(widths[i] if i < len(widths) else 0)
                         for i, x in enumerate(row)).rstrip()

    if not a.no_header and fmt != 'json':
        if fmt == 'table':
            h = line(cols)
            out.write(f'\x1b[1m{h}\x1b[0m\n' if tty and 'NO_COLOR' not in os.environ else h + '\n')
        else:
            writer.writerow(cols)

    grep = a.grep.lower() if a.grep else None
    n = recs = emitted = 0
    try:
        for ts, link, data in stream.packets(threading_event()):
            d = decode(link, data)
            if d is None:
                continue
            n += 1
            parsed = prof.parse(d)
            if parsed:
                rows = parsed
                recs += len(parsed)
            elif a.unparsed and d['payload']:
                rows = [None]
            else:
                continue
            t = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            meta = [n, t, addr(d['src'], d['sport']), addr(d['dst'], d['dport']), d['proto'], len(data)]
            for rec in rows:
                if rec is None:
                    rec = [d['payload'][:120].decode('utf-8', 'replace')]
                vals = rec + [''] * (nf - len(rec))
                row = vals if a.no_meta else meta + vals
                if grep and grep not in ' '.join(map(str, row)).lower():
                    continue
                if fmt == 'json':
                    obj = {} if a.no_meta else dict(zip(META, meta))
                    obj['data'] = {(names[i] if i < nf else f'extra{i + 1 - nf}'): v for i, v in enumerate(vals)}
                    out.write(json.dumps(obj, ensure_ascii=False) + '\n')
                elif fmt == 'table':
                    out.write(line(row) + '\n')
                else:
                    writer.writerow(row)
                emitted += 1
                if flush_each:
                    out.flush()
                if a.count and emitted >= a.count:
                    raise StopIteration
    except StopIteration:
        pass
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except PcapError as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    finally:
        try:
            out.flush()
        except BrokenPipeError:
            pass
    if not a.quiet:
        print(f'[{prof.name}] {n:,} packets, {recs:,} records, {emitted:,} rows output', file=sys.stderr)
    return 0


def threading_event():
    import threading
    return threading.Event()
