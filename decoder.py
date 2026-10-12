"""Minimal L2-L4 decoder: Ethernet/VLAN, Linux SLL/SLL2, loopback, raw IP -> IPv4/IPv6 -> TCP/UDP/ICMP."""
import socket

_FLAGS = [(0x02, 'S'), (0x10, 'A'), (0x08, 'P'), (0x01, 'F'), (0x04, 'R')]


def decode(link, d):
    try:
        return _decode(link, d)
    except (IndexError, ValueError):
        return None


def _decode(link, d):
    if link == 1:
        et, off = int.from_bytes(d[12:14], 'big'), 14
        while et in (0x8100, 0x88A8):
            et = int.from_bytes(d[off + 2:off + 4], 'big')
            off += 4
    elif link == 113:
        et, off = int.from_bytes(d[14:16], 'big'), 16
    elif link == 276:
        et, off = int.from_bytes(d[0:2], 'big'), 20
    elif link in (0, 108):
        off = 4
        et = 0x0800 if d[4] >> 4 == 4 else 0x86DD
    elif link in (101, 12, 14):
        off = 0
        et = 0x0800 if d[0] >> 4 == 4 else 0x86DD
    else:
        return None

    if et == 0x0800:
        ihl = (d[off] & 15) * 4
        tot = int.from_bytes(d[off + 2:off + 4], 'big')
        proto = d[off + 9]
        src = socket.inet_ntop(socket.AF_INET, d[off + 12:off + 16])
        dst = socket.inet_ntop(socket.AF_INET, d[off + 16:off + 20])
        end = min(off + tot, len(d)) if tot >= ihl else len(d)
        l4 = off + ihl
        if int.from_bytes(d[off + 6:off + 8], 'big') & 0x1FFF:
            proto = -1  # non-first fragment
    elif et == 0x86DD:
        proto = d[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, d[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, d[off + 24:off + 40])
        plen = int.from_bytes(d[off + 4:off + 6], 'big')
        end = min(off + 40 + plen, len(d)) if plen else len(d)
        l4 = off + 40
        while proto in (0, 43, 60, 44):
            nxt = d[l4]
            l4 += 8 if proto == 44 else (d[l4 + 1] + 1) * 8
            proto = nxt
    else:
        return None

    sport = dport = 0
    payload, name, flags = b'', 'IP', ''
    if proto == 6:
        name = 'TCP'
        sport = int.from_bytes(d[l4:l4 + 2], 'big')
        dport = int.from_bytes(d[l4 + 2:l4 + 4], 'big')
        payload = d[l4 + (d[l4 + 12] >> 4) * 4:end]
        fl = d[l4 + 13]
        flags = ''.join(c for bit, c in _FLAGS if fl & bit)
    elif proto == 17:
        name = 'UDP'
        sport = int.from_bytes(d[l4:l4 + 2], 'big')
        dport = int.from_bytes(d[l4 + 2:l4 + 4], 'big')
        ulen = int.from_bytes(d[l4 + 4:l4 + 6], 'big')
        uend = min(l4 + ulen, end) if ulen >= 8 else end
        payload = d[l4 + 8:uend]
    elif proto in (1, 58):
        name = 'ICMP' if proto == 1 else 'ICMPv6'
    elif proto >= 0:
        name = f'IP/{proto}'
    return dict(src=src, dst=dst, sport=sport, dport=dport, proto=name, payload=payload, flags=flags)


def addr(ip, port):
    if not port:
        return ip
    return f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'


def printable(b, nl=True):
    return ''.join(chr(c) if 32 <= c < 127 or (nl and c in (9, 10, 13)) else '.' for c in b)
