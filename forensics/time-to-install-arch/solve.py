import collections
import socket
import struct
import sys

import dpkt


TARGET = "158.160.214.233"
PCAP = sys.argv[1] if len(sys.argv) > 1 else "task.pcap"
NONCE = bytes.fromhex("0aad23b18f07c20ea30a2b49")
KEY = bytes.fromhex(
    "4752454153456368616e6e656c212121"
    "deadbeefcafebabe13374200900df00d"
)


def rol(value, count):
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def chacha_block(counter):
    initial = [0xDEADBEEF, 0xCAFEBABE, 0x13371337, 0xC0FFEE42]
    initial += list(struct.unpack("<8I", KEY))
    initial += [counter]
    initial += list(struct.unpack("<3I", NONCE))
    state = initial[:]

    def qr(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = rol(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = rol(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = rol(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = rol(state[b] ^ state[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)

    words = ((a + b) & 0xFFFFFFFF for a, b in zip(state, initial))
    return struct.pack("<16I", *words)


def join_tcp(parts):
    parts.sort()
    result = bytearray()
    base = parts[0][0]

    for seq, data in parts:
        offset = seq - base
        if offset < len(result):
            data = data[len(result) - offset :]
            offset = len(result)
        if offset == len(result):
            result += data

    return bytes(result)


def tls_records(data):
    pos = 0
    while pos + 5 <= len(data):
        size = int.from_bytes(data[pos + 3 : pos + 5], "big")
        if pos + 5 + size > len(data):
            break
        yield data[pos], data[pos + 5 : pos + 5 + size]
        pos += 5 + size


def handshakes(data):
    pos = 0
    while pos + 4 <= len(data):
        size = int.from_bytes(data[pos + 1 : pos + 4], "big")
        if pos + 4 + size > len(data):
            break
        yield data[pos], data[pos + 4 : pos + 4 + size]
        pos += 4 + size


def get_grease(body, client):
    sid_len = body[34]
    sid = body[35 : 35 + sid_len]
    pos = 35 + sid_len

    if client:
        cipher_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2 + cipher_len
        compression_len = body[pos]
        pos += 1 + compression_len
    else:
        pos += 3

    end = pos + 2 + int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    grease = None

    while pos + 4 <= end:
        kind = int.from_bytes(body[pos : pos + 2], "big")
        size = int.from_bytes(body[pos + 2 : pos + 4], "big")
        value = body[pos + 4 : pos + 4 + size]
        if kind == 0x0A0A:
            grease = value
        pos += 4 + size

    return sid, grease


flows = collections.defaultdict(lambda: {"client": [], "server": []})

with open(PCAP, "rb") as f:
    for _, raw in dpkt.pcap.Reader(f):
        try:
            ip = dpkt.ethernet.Ethernet(raw).data
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
                continue

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            if dst == TARGET and tcp.dport == 443:
                flows[tcp.sport]["client"].append((tcp.seq, bytes(tcp.data)))
            elif src == TARGET and tcp.sport == 443:
                flows[tcp.dport]["server"].append((tcp.seq, bytes(tcp.data)))
        except Exception:
            pass


rows = []

for flow in flows.values():
    row = {}
    for direction, hello_type in (("client", 1), ("server", 2)):
        if not flow[direction]:
            continue
        for record_type, payload in tls_records(join_tcp(flow[direction])):
            if record_type != 22:
                continue
            for handshake_type, body in handshakes(payload):
                if handshake_type == hello_type:
                    sid, ext = get_grease(body, direction == "client")
                    row[direction] = ext
                    if direction == "client":
                        row["counter"] = int.from_bytes(sid[-4:], "little")

    if len(row) == 3:
        rows.append(row)

rows.sort(key=lambda row: row["counter"])

client_frames = []
server_frames = []

for row in rows:
    i = row["counter"]
    client_frames.append(
        bytes(a ^ b for a, b in zip(row["client"], chacha_block(2 * i)))
    )
    server_frames.append(
        bytes(a ^ b for a, b in zip(row["server"], chacha_block(2 * i + 1)))
    )


def print_messages(name, frames):
    start = None
    message = bytearray()

    for i, frame in enumerate(frames + [bytes(16)]):
        if frame[0] in (2, 4):
            if start is None:
                start = i
            message += frame[1:]
        elif start is not None:
            value = bytes(message).rstrip(b"\0")
            if value:
                print(f"{name} {start}-{i - 1}: {value!r}")
            start = None
            message = bytearray()


print_messages("SERVER", server_frames)
print_messages("CLIENT", client_frames)


