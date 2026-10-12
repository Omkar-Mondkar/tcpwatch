#!/usr/bin/env python3
"""Writes a fake live pcap with '|' separated UDP payloads so you can try the GUI:
   python sample_feed.py live.pcap   (leave running)   then   python main.py live.pcap"""
import random, struct, sys, time

out = sys.argv[1] if len(sys.argv) > 1 else 'live.pcap'
users, acts = ['alice', 'bob', 'carol', 'dave'], ['LOGIN', 'LOGOUT', 'BUY', 'VIEW']
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    f.flush()
    i = 0
    while True:
        i += 1
        pay = (f'{1000 + i}|{random.choice(users)}|{random.choice(acts)}|'
               f'{random.randint(1, 500)}.{random.randint(0, 99):02d}|{random.choice(["ok", "fail"])}\n').encode()
        udp = struct.pack('!HHHH', 40000 + i % 100, 9000, 8 + len(pay), 0) + pay
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), i & 0xFFFF, 0, 64, 17, 0,
                         bytes([10, 0, 0, 1 + i % 5]), bytes([10, 0, 0, 100])) + udp
        eth = bytes.fromhex('aabbccddeeff112233445566') + b'\x08\x00' + ip
        t = time.time()
        f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(eth), len(eth)) + eth)
        f.flush()
        time.sleep(random.uniform(0.05, 0.4))
