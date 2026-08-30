import hashlib
import os


BLOCK_SIZE = 16
FIELD = 4093
GENERATOR = 2
SPECTRUM_SIZE = 56

SBOX = (6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11)
ROW_SHIFTS = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
MIX_LEFT = (0, 1, 5, 9, 13, 3, 7, 11, 15, 2, 6, 10, 14, 4, 8, 12)
MIX_RIGHT = (7, 11, 3, 13, 5, 15, 9, 1, 14, 6, 12, 4, 10, 2, 8, 0)


def derive(key, label):
    return hashlib.sha256(key + b"\x00" + label).digest()


class HashStream:
    def __init__(self, key, label):
        self.key = key
        self.label = label
        self.counter = 0
        self.buffer = bytearray()

    def take(self, amount):
        while len(self.buffer) < amount:
            counter = self.counter.to_bytes(8, "big")
            self.buffer.extend(hashlib.sha256(self.key + b"\x00" + self.label + counter).digest())
            self.counter += 1
        result = bytes(self.buffer[:amount])
        del self.buffer[:amount]
        return result

    def randbelow(self, limit):
        ceiling = (1 << 32) - ((1 << 32) % limit)
        while True:
            value = int.from_bytes(self.take(4), "big")
            if value < ceiling:
                return value % limit

    def shuffle(self, values):
        values = list(values)
        for i in range(len(values) - 1, 0, -1):
            j = self.randbelow(i + 1)
            values[i], values[j] = values[j], values[i]
        return values


def grouped_permutation(rng):
    result = []
    for group in rng.shuffle(range(4)):
        result.extend(rng.shuffle(range(group * 4, group * 4 + 4)))
    return result


def inverse_permutation(values):
    result = [0] * len(values)
    for i, value in enumerate(values):
        result[value] = i
    return result


def rotl4(value, amount):
    amount &= 3
    value &= 15
    if amount == 0:
        return value
    return ((value << amount) | (value >> (4 - amount))) & 15


def rotl8(value, amount):
    amount &= 7
    value &= 255
    if amount == 0:
        return value
    return ((value << amount) | (value >> (8 - amount))) & 255


def rotl16(value, amount):
    amount &= 15
    value &= 65535
    if amount == 0:
        return value
    return ((value << amount) | (value >> (16 - amount))) & 65535


def feistel_f(value, key, rnd):
    changed = (SBOX[value >> 4] << 4) | SBOX[value & 15]
    changed = (changed + key + 19 * rnd) & 255
    return rotl8(changed, rnd + 1) ^ ((value * 0x3D) & 255)


def public_wrapper(word, rank):
    left = word >> 8
    right = word & 255
    for rnd in range(4):
        key = (0x53 + rank * 0x29 + rnd * 0x47) & 255
        left, right = right, left ^ feistel_f(right, key, rnd)
    return (left << 8) | right


def public_wrapper_inv(word, rank):
    left = word >> 8
    right = word & 255
    for rnd in range(3, -1, -1):
        key = (0x53 + rank * 0x29 + rnd * 0x47) & 255
        left, right = right ^ feistel_f(left, key, rnd), left
    return (left << 8) | right


def diffuse_words(words):
    if len(words) != 16:
        raise ValueError("expected 16 words")
    forward = [words[0]]
    for i in range(1, 16):
        forward.append(words[i] ^ rotl16(forward[-1], MIX_LEFT[i]))

    result = [0] * 16
    result[15] = forward[15]
    for i in range(14, -1, -1):
        result[i] = forward[i] ^ rotl16(result[i + 1], -MIX_RIGHT[i])
    return result


def undiffuse_words(words):
    if len(words) != 16:
        raise ValueError("expected 16 words")
    forward = [0] * 16
    forward[15] = words[15]
    for i in range(14, -1, -1):
        forward[i] = words[i] ^ rotl16(words[i + 1], -MIX_RIGHT[i])

    result = [forward[0]]
    for i in range(1, 16):
        result.append(forward[i] ^ rotl16(forward[i - 1], MIX_LEFT[i]))
    return result


def unpack_rank_words(ciphertext):
    if len(ciphertext) != 32:
        raise ValueError("ciphertext block must be 32 bytes")
    words = [int.from_bytes(ciphertext[i:i + 2], "big") for i in range(0, 32, 2)]
    words = undiffuse_words(words)
    return [public_wrapper_inv(word, rank) for rank, word in enumerate(words)]


def split_word(word):
    return word >> 12, (word >> 8) & 15, (word >> 4) & 15, word & 15


def pkcs7_pad(data):
    amount = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([amount]) * amount


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("invalid padded length")
    amount = data[-1]
    if amount < 1 or amount > BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid padding")
    return data[:-amount]


def symbol_permutation_from_model(nodes, coefficients):
    data = bytearray(b"spectral-model")
    for node in nodes:
        data.extend(node.to_bytes(2, "big"))
    for lane in coefficients:
        for value in lane:
            data.extend(value.to_bytes(2, "big"))
    key = hashlib.sha256(data).digest()
    return HashStream(key, b"hexadoku-symbols").shuffle(range(16))


def make_spectral_model(instance_key):
    rng = HashStream(instance_key, b"spectrum")
    exponents = rng.shuffle(range(1, FIELD - 1))[:SPECTRUM_SIZE]
    nodes = sorted(pow(GENERATOR, exponent, FIELD) for exponent in exponents)

    coefficients = []
    for _ in range(16):
        coefficients.append([rng.randbelow(FIELD - 1) + 1 for _ in nodes])
    return nodes, coefficients


class SpectrumGenerator:
    def __init__(self, nodes, coefficients):
        self.nodes = list(nodes)
        self.coefficients = [list(row) for row in coefficients]
        self.state = [list(row) for row in coefficients]
        self.block_number = 0
        self.folded = False

    def next_block(self):
        result = [sum(row) % FIELD for row in self.state]
        for lane, row in enumerate(self.state):
            self.state[lane] = [row[j] * self.nodes[j] % FIELD for j in range(len(row))]
        self.block_number += 1
        return result

    def fold_for_flag(self):
        if self.folded:
            raise RuntimeError("stream was already folded")
        for lane, row in enumerate(self.state):
            for j, node in enumerate(self.nodes):
                shift = 1 + (
                    self.coefficients[lane][j] * (lane + 1) + (j + 3) * (j + 7)
                ) % (FIELD - 1)
                row[j] = row[j] * pow(node, shift, FIELD) % FIELD
        self.folded = True

    def copy(self):
        result = SpectrumGenerator(self.nodes, self.coefficients)
        result.state = [list(row) for row in self.state]
        result.block_number = self.block_number
        result.folded = self.folded
        return result


def block_rotation(values, block_number):
    return (sum(values) + 3 * values[0] + block_number) & 15


class SudoKrypt:
    def __init__(self, seed, flag, query_limit, session_nonce=None):
        if isinstance(flag, str):
            flag = flag.encode()
        if session_nonce is None:
            session_nonce = os.urandom(16)

        master = seed if isinstance(seed, bytes) else str(seed).encode()
        self.instance_key = derive(master, b"session/" + session_nonce)
        self.flag = flag
        self.remaining = query_limit
        self.session_nonce = session_nonce
        self.flag_taken = False

        self.nodes, self.coefficients = make_spectral_model(self.instance_key)
        self.prng = SpectrumGenerator(self.nodes, self.coefficients)
        self.build_hexadoku()

    def build_hexadoku(self):
        rows = grouped_permutation(HashStream(self.instance_key, b"rows"))
        cols = grouped_permutation(HashStream(self.instance_key, b"columns"))
        self.symbol_perm = symbol_permutation_from_model(self.nodes, self.coefficients)
        self.symbol_inv = inverse_permutation(self.symbol_perm)
        self.q_perm = HashStream(self.instance_key, b"q-labels").shuffle(range(16))
        self.q_inv = inverse_permutation(self.q_perm)

        self.board = []
        for physical_row in range(16):
            row = []
            source_row = rows[physical_row]
            for physical_col in range(16):
                source_col = cols[physical_col]
                value = (ROW_SHIFTS[source_row] + source_col) & 15
                row.append(self.symbol_perm[value])
            self.board.append(row)

        self.row_for_shift = [0] * 16
        for physical_row, source_row in enumerate(rows):
            self.row_for_shift[ROW_SHIFTS[source_row]] = physical_row
        self.col_for_base = inverse_permutation(cols)

    def inner_word(self, byte, stream_value):
        q = byte >> 4
        symbol = ((byte & 15) - q) & 15
        high = stream_value >> 8
        mask = (stream_value >> 4) & 15
        low = stream_value & 15

        row_code = SBOX[low]
        base_col = (self.symbol_inv[symbol] - row_code) & 15
        physical_row = self.row_for_shift[row_code]
        physical_col = self.col_for_base[base_col]
        if self.board[physical_row][physical_col] != symbol:
            raise RuntimeError("broken Hexadoku instance")

        row_field = (row_code + mask) & 15
        col_field = (base_col + 2 * mask) & 15
        check = high ^ SBOX[(row_code ^ rotl4(base_col, 1) ^ q ^ low) & 15]
        return (self.q_perm[q] << 12) | (row_field << 8) | (col_field << 4) | check

    def decode_inner_word(self, word, stream_value):
        q_label, row_field, col_field, check_field = split_word(word)
        q = self.q_inv[q_label]
        high = stream_value >> 8
        mask = (stream_value >> 4) & 15
        low = stream_value & 15
        row_code = SBOX[low]
        base_col = (col_field - 2 * mask) & 15

        if row_field != (row_code + mask) & 15:
            raise ValueError("row field mismatch")
        check = high ^ SBOX[(row_code ^ rotl4(base_col, 1) ^ q ^ low) & 15]
        if check_field != check:
            raise ValueError("check field mismatch")

        symbol = self.symbol_perm[(row_code + base_col) & 15]
        return (q << 4) | ((symbol + q) & 15)

    def crypt_block(self, plaintext):
        if len(plaintext) != BLOCK_SIZE:
            raise ValueError("plaintext must be exactly 16 bytes")
        block_number = self.prng.block_number
        values = self.prng.next_block()
        words = [self.inner_word(byte, values[i]) for i, byte in enumerate(plaintext)]

        rotation = block_rotation(values, block_number)
        ranked = [words[(rank + rotation) & 15] for rank in range(16)]
        wrapped = [public_wrapper(word, rank) for rank, word in enumerate(ranked)]
        mixed = diffuse_words(wrapped)
        return b"".join(word.to_bytes(2, "big") for word in mixed)

    def encrypt_block(self, plaintext):
        if self.flag_taken:
            raise RuntimeError("encrypt oracle is closed after encrypted flag")
        if len(plaintext) != BLOCK_SIZE:
            raise ValueError("plaintext must be exactly 16 bytes")
        if self.remaining <= 0:
            raise RuntimeError("query limit exceeded")
        self.remaining -= 1
        return self.crypt_block(plaintext)

    def encrypt_flag(self):
        if self.flag_taken:
            raise RuntimeError("encrypted flag was already requested")
        self.flag_taken = True
        self.prng.fold_for_flag()
        padded = pkcs7_pad(self.flag)
        blocks = []
        for offset in range(0, len(padded), BLOCK_SIZE):
            blocks.append(self.crypt_block(padded[offset:offset + BLOCK_SIZE]))
        return b"".join(blocks)

