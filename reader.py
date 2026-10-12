"""Live pcap reader (classic pcap, as written by `tcpdump -w`). Follows a growing file like `tail -f`."""
import os, struct, sys, time

MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}


class PcapError(Exception):
    pass


class PcapStream:
    def __init__(self, source, follow=True):
        self.source, self.follow = source, follow
        self.stdin = source == '-'
        self.f = None
        self.waiting = False   # True once the reader has caught up with the end of the file
        self.on_idle = None    # callback fired when catching up (CLI flushes output here)

    def _open(self, stop):
        if self.stdin:
            self.f = sys.stdin.buffer
            return True
        while not os.path.exists(self.source):
            if not self.follow or stop.is_set():
                return False
            time.sleep(0.2)
        self.f = open(self.source, 'rb')
        return True

    def _read(self, n, stop):
        buf = b''
        while len(buf) < n:
            chunk = self.f.read(n - len(buf))
            if chunk:
                self.waiting = False
                buf += chunk
            elif self.stdin or not self.follow or stop.is_set():
                return None
            else:
                if not self.waiting:
                    self.waiting = True
                    if self.on_idle:
                        self.on_idle()
                time.sleep(0.03)  # wait for writer to append more
        return buf

    def packets(self, stop):
        """Yield (timestamp, linktype, raw_bytes)."""
        if not self._open(stop):
            return
        hdr = self._read(24, stop)
        if not hdr:
            return
        if hdr[:4] == b'\x0a\x0d\x0d\x0a':
            raise PcapError('pcapng is not supported - capture with `tcpdump -w` (classic pcap)')
        if hdr[:4] not in MAGICS:
            raise PcapError('Not a pcap file')
        end, res = MAGICS[hdr[:4]]
        link = struct.unpack(end + 'I', hdr[20:24])[0] & 0x0FFFFFFF
        while not stop.is_set():
            rh = self._read(16, stop)
            if not rh:
                return
            sec, frac, incl, _orig = struct.unpack(end + 'IIII', rh)
            if incl > 1 << 20:
                raise PcapError('Corrupt record header')
            data = self._read(incl, stop)
            if data is None:
                return
            yield sec + frac * res, link, data
