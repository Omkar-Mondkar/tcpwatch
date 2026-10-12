#!/usr/bin/env python3
"""Writes a fake live pcap so you can try the tool:
   python sample_feed.py live.pcap          '|' positional rows
   python sample_feed.py live.pcap kv       Level|Time|Msg|key|value|... rows with varying keys
 (leave running) then:  python main.py live.pcap"""
import datetime, random, struct, sys, time

out = sys.argv[1] if len(sys.argv) > 1 else 'live.pcap'
kv = len(sys.argv) > 2 and sys.argv[2] == 'kv'
users, acts = ['alice', 'bob', 'carol', 'dave'], ['LOGIN', 'LOGOUT', 'BUY', 'VIEW']


def payload(i):
    if not kv:
        return (f'{1000 + i}|{random.choice(users)}|{random.choice(acts)}|'
                f'{random.randint(1, 500)}.{random.randint(0, 99):02d}|{random.choice(["ok", "fail"])}\n').encode()
    now = datetime.datetime.now().strftime('%H:%M:%S.%f')
    tok = random.choice([44592, 1333, 2885])
    if random.random() < .6:
        return (f'DEBUG|{now}|LTP_MSG1|Ex\x00|12|SN|{51833000 + i}|Token| {tok}\x00|LTP|  {random.randint(1000, 99999)}'
                f'|OpenInterest|{random.randint(10**6, 10**7)}|FeedTimestamp|{random.randint(10**14, 10**15)}\x00\x00\n').encode()
    return (f'DEBUG|{now}|DEPTH_MSG2|Ex|12|SN|{51833000 + i}|Token|{tok}|BidPrice|{random.randint(900, 999)}'
            f'|BidQty|{random.randint(1, 500)}|AskPrice|{random.randint(1000, 1100)}|AskQty|{random.randint(1, 500)}\n').encode()


with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    f.flush()
    i = 0
    while True:
        i += 1
        pay = payload(i)
        udp = struct.pack('!HHHH', 40000 + i % 100, 9000, 8 + len(pay), 0) + pay
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), i & 0xFFFF, 0, 64, 17, 0,
                         bytes([10, 0, 0, 1 + i % 5]), bytes([10, 0, 0, 100])) + udp
        eth = bytes.fromhex('aabbccddeeff112233445566') + b'\x08\x00' + ip
        t = time.time()
        f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(eth), len(eth)) + eth)
        f.flush()
        time.sleep(random.uniform(0.05, 0.4))
