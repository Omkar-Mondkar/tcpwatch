#!/usr/bin/env python3
"""tcpwatch - parse tcpdump pcap files/streams with configurable '|'-style data patterns (GUI + CLI).

The whole file is parsed from the first packet to the last; then, unless --no-follow is given,
new packets appended by tcpdump are parsed as they arrive.

  tcpdump -i eth0 -U -w live.pcap &
  python main.py live.pcap                      # GUI (falls back to CLI if no display / no tkinter)
  python main.py --cli live.pcap                # CLI, table output
  python main.py --cli live.pcap --no-follow -f csv -o out.csv
  python main.py --cli live.pcap -d ';' -F id,user,action --grep login
  tcpdump -i any -U -w - | python main.py --cli -
"""
import argparse, os, sys

from patterns import PatternStore


def parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('pcap', nargs='?', help="pcap file (live or finished), or '-' for stdin")
    g = ap.add_argument_group('mode')
    g.add_argument('--cli', action='store_true', help='run in the terminal (no GUI)')
    g.add_argument('--gui', action='store_true', help='force the GUI')
    g.add_argument('--no-follow', action='store_true', help='exit at end of file instead of waiting for new packets')
    g = ap.add_argument_group('patterns')
    g.add_argument('-c', '--config', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patterns.json'),
                   help='patterns file (default: patterns.json next to main.py)')
    g.add_argument('-p', '--profile', help='pattern profile to use')
    g.add_argument('--list-profiles', action='store_true', help='list profiles and exit')
    g.add_argument('-d', '--delimiter', help="override delimiter (e.g. '|', ';', '\\t')")
    g.add_argument('-F', '--fields', help='override field names, comma separated')
    g.add_argument('-r', '--regex', help='override record regex (group 1 = record)')
    g.add_argument('--proto', choices=['any', 'tcp', 'udp'], help='only parse this protocol')
    g.add_argument('--port', type=int, help='only parse packets using this port')
    g.add_argument('--min-fields', type=int, help='minimum fields for a record to count')
    g = ap.add_argument_group('CLI output')
    g.add_argument('-f', '--format', choices=['table', 'csv', 'tsv', 'json'], default='table', help='default: table')
    g.add_argument('-o', '--output', help='write to file instead of stdout')
    g.add_argument('-n', '--count', type=int, help='stop after N output rows')
    g.add_argument('--grep', help='only output rows containing this text (case-insensitive)')
    g.add_argument('--unparsed', action='store_true', help='also output packets whose payload did not match')
    g.add_argument('--no-meta', action='store_true', help='only the parsed fields, no #/time/src/dst/proto/len')
    g.add_argument('--no-header', action='store_true', help='omit the header line')
    g.add_argument('-q', '--quiet', action='store_true', help='no summary on stderr')
    g = ap.add_argument_group('GUI')
    g.add_argument('--max-rows', type=int, default=500000, help='rows kept in the GUI table, 0 = unlimited (default 500000)')
    return ap


def gui_available():
    try:
        import tkinter  # noqa
    except ImportError:
        return False
    if sys.platform.startswith('linux') and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        return False
    return True


def main():
    a = parser().parse_args()
    store = PatternStore(a.config)
    if a.list_profiles:
        for n in store.profiles:
            print(('* ' if n == store.active else '  ') + n)
        return 0
    if not a.pcap:
        parser().error('pcap file required')
    use_cli = a.cli
    if not use_cli and not a.gui and not gui_available():
        print('tcpwatch: no display / tkinter available, running in CLI mode', file=sys.stderr)
        use_cli = True
    if use_cli:
        from cli import run
        return run(a, store)
    if a.profile:
        if a.profile not in store.profiles:
            sys.exit(f'unknown profile {a.profile!r}')
        store.active = a.profile
    import tkinter as tk
    from gui import App
    try:  # crisp text on Windows high-DPI screens
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root, a.pcap, store, not a.no_follow, a.max_rows)
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
