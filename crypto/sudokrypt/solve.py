import argparse
import re
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "static"))
from sudokrypt_core import (
    FIELD, SBOX, block_rotation, pkcs7_unpad, split_word,
    unpack_rank_words,
)

HOST = "tcp.sasc.tf"
PORT = 31415
ORDER = FIELD - 1
SPECTRUM = 56
QUERIES = 96


def invert_permutation(p):
    out = [0] * len(p)
    for i, v in enumerate(p):
        out[v] = i
    return out


def decode_stream_candidate(word, q, symbol_inverse):
    qlabel, row_field, col_field, check_field = split_word(word)
    possible = []
    for value in range(FIELD):
        high = value >> 8
        mask = (value >> 4) & 15
        low = value & 15
        row_code = SBOX[low]
        base_col = (symbol_inverse - row_code) & 15
        if row_field != (row_code + mask) & 15:
            continue
        if col_field != (base_col + 2 * mask) & 15:
            continue
        check = high ^ SBOX[(row_code ^ (((base_col << 1) | (base_col >> 3)) & 15) ^ q ^ low) & 15]
        if check_field == check:
            possible.append(value)
    return qlabel, possible


def recover_block(ciphertext, block_number, byte, known_symbol_inverse=None, used_inverses=(), allow_many=False):
    q = byte >> 4
    symbol = ((byte & 15) - q) & 15
    ranked = unpack_rank_words(ciphertext)
    qlabels = {split_word(w)[0] for w in ranked}
    if len(qlabels) != 1:
        raise RuntimeError("q labels disagree")
    inverses = [known_symbol_inverse] if known_symbol_inverse is not None else [
        k for k in range(16) if k not in used_inverses
    ]
    candidates = []
    for k in inverses:
        ranked_values = []
        for word in ranked:
            _, vals = decode_stream_candidate(word, q, k)
            if len(vals) != 1:
                break
            ranked_values.append(vals[0])
        if len(ranked_values) != 16:
            continue
        for rotation in range(16):
            values = [ranked_values[(lane - rotation) & 15] for lane in range(16)]
            if block_rotation(values, block_number) == rotation:
                candidates.append((k, values, next(iter(qlabels))))
    if allow_many:
        return symbol, candidates
    if len(candidates) != 1:
        raise RuntimeError(f"block {block_number}: expected one decode, got {len(candidates)}")
    return symbol, candidates[0]


def gauss_solve(matrix, rhs_cols, p=FIELD):
    # Matrix is square; rhs_cols is a list of RHS vectors.
    n = len(matrix)
    aug = [[x % p for x in matrix[i]] + [rhs[i] % p for rhs in rhs_cols]
           for i in range(n)]
    width = n + len(rhs_cols)
    for col in range(n):
        pivot = next(i for i in range(col, n) if aug[i][col])
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = pow(aug[col][col], -1, p)
        aug[col] = [x * inv % p for x in aug[col]]
        for i in range(n):
            if i != col and aug[i][col]:
                f = aug[i][col]
                aug[i] = [(aug[i][j] - f * aug[col][j]) % p for j in range(width)]
    return [[aug[i][n + r] for i in range(n)] for r in range(len(rhs_cols))]


def recover_recurrence(sequences):
    sample_count=len(sequences[0])
    rows, rhs = [], []
    for lane in range(16):
        seq = sequences[lane]
        for n in range(sample_count - SPECTRUM):
            rows.append(seq[n:n + SPECTRUM])
            rhs.append((-seq[n + SPECTRUM]) % FIELD)
    # Select 56 independent equations with modular elimination.
    basis = []
    pivots = []
    chosen_rows, chosen_rhs = [], []
    for row, value in zip(rows, rhs):
        v = [x % FIELD for x in row]
        for pivot, b in zip(pivots, basis):
            if v[pivot]:
                f = v[pivot]
                v = [(v[j] - f * b[j]) % FIELD for j in range(SPECTRUM)]
        pivot = next((j for j, x in enumerate(v) if x), None)
        if pivot is None:
            continue
        inv = pow(v[pivot], -1, FIELD)
        v = [x * inv % FIELD for x in v]
        # Maintain echelon rows; forward reduction is sufficient for independence.
        pivots.append(pivot)
        basis.append(v)
        chosen_rows.append(row)
        chosen_rhs.append(value)
        if len(chosen_rows) == SPECTRUM:
            break
    if len(chosen_rows) != SPECTRUM:
        raise RuntimeError("recurrence system has low rank")
    coeffs = gauss_solve(chosen_rows, [chosen_rhs])[0]
    for row, value in zip(rows, rhs):
        if sum(a*b for a,b in zip(row,coeffs)) % FIELD != value:
            raise RuntimeError("recurrence verification failed")
    return coeffs


def polynomial_value(coeffs, x):
    # x^56 + coeffs[55]x^55 + ... + coeffs[0]
    value = 1
    for c in reversed(coeffs):
        value = (value*x + c) % FIELD
    return value


def recover_model(sequences, offset=0):
    recurrence = recover_recurrence(sequences)
    nodes = [x for x in range(1, FIELD) if polynomial_value(recurrence, x) == 0]
    if len(nodes) != SPECTRUM:
        raise RuntimeError(f"expected {SPECTRUM} roots, got {len(nodes)}")
    vandermonde = [[pow(node, n, FIELD) for node in nodes] for n in range(SPECTRUM)]
    rhs_cols = [[sequences[lane][n] for n in range(SPECTRUM)] for lane in range(16)]
    shifted = gauss_solve(vandermonde, rhs_cols)
    coefficients = [[shifted[lane][j] * pow(pow(nodes[j],offset,FIELD),-1,FIELD) % FIELD
                     for j in range(SPECTRUM)] for lane in range(16)]
    for lane in range(16):
        for n in range(len(sequences[lane])):
            got = sum(coefficients[lane][j] * pow(nodes[j], n+offset, FIELD) for j in range(SPECTRUM)) % FIELD
            if got != sequences[lane][n]:
                raise RuntimeError("spectral model verification failed")
    return nodes, coefficients


def folded_stream(nodes, coefficients, blocks):
    state = []
    for lane in range(16):
        row = []
        for j,node in enumerate(nodes):
            value = coefficients[lane][j] * pow(node, QUERIES, FIELD) % FIELD
            shift = 1 + (coefficients[lane][j] * (lane + 1) + (j + 3) * (j + 7)) % ORDER
            row.append(value * pow(node, shift, FIELD) % FIELD)
        state.append(row)
    output = []
    for _ in range(blocks):
        output.append([sum(row) % FIELD for row in state])
        for lane in range(16):
            state[lane] = [state[lane][j] * nodes[j] % FIELD for j in range(SPECTRUM)]
    return output


def decode_inner(word, stream_value, q_inv, symbol_perm):
    q_label,row_field,col_field,check_field = split_word(word)
    q=q_inv[q_label]
    high=stream_value>>8; mask=(stream_value>>4)&15; low=stream_value&15
    row_code=SBOX[low]
    base_col=(col_field-2*mask)&15
    if row_field != (row_code+mask)&15:
        raise RuntimeError("row mismatch")
    check=high ^ SBOX[(row_code ^ (((base_col<<1)|(base_col>>3))&15) ^ q ^ low)&15]
    if check_field != check:
        raise RuntimeError("check mismatch")
    symbol=symbol_perm[(row_code+base_col)&15]
    return (q<<4)|((symbol+q)&15)


def decrypt_flag(ciphertext, streams, q_perm, symbol_inv):
    symbol_perm=[0]*16
    for symbol,k in enumerate(symbol_inv):
        symbol_perm[k]=symbol
    q_inv=invert_permutation(q_perm)
    plain=bytearray()
    for bno,offset in enumerate(range(0,len(ciphertext),32),start=QUERIES):
        ranked=unpack_rank_words(ciphertext[offset:offset+32])
        values=streams[bno-QUERIES]
        rotation=block_rotation(values,bno)
        words=[ranked[(lane-rotation)&15] for lane in range(16)]
        plain.extend(decode_inner(words[i],values[i],q_inv,symbol_perm) for i in range(16))
    return pkcs7_unpad(bytes(plain))


def recvuntil(sock, marker):
    data=bytearray()
    while marker not in data:
        chunk=sock.recv(4096)
        if not chunk: raise EOFError
        data.extend(chunk)
    return bytes(data)


def variable_plaintext(symbol):
    return bytes((q<<4)|((symbol+q)&15) for q in range(16))


def recover_variable_block(ciphertext, block_number, symbol, q_inv, known_k=None, used=(), allow_many=False):
    ranked=unpack_rank_words(ciphertext)
    rotations=[]
    for rank,word in enumerate(ranked):
        q=q_inv[split_word(word)[0]]
        rotations.append((q-rank)&15)
    if len(set(rotations))!=1:
        raise RuntimeError("inconsistent ranked q labels")
    rotation=rotations[0]
    candidates=[]
    for k in ([known_k] if known_k is not None else [x for x in range(16) if x not in used]):
        values=[]
        for lane in range(16):
            word=ranked[(lane-rotation)&15]
            _,possible=decode_stream_candidate(word,lane,k)
            if len(possible)!=1:
                break
            values.append(possible[0])
        if len(values)==16 and block_rotation(values,block_number)==rotation:
            candidates.append((k,values))
    if allow_many:
        return candidates
    if len(candidates)!=1:
        raise RuntimeError(f"variable block {block_number}: got {len(candidates)} candidates")
    return candidates[0]


def solve_oracle(encrypt, encrypt_flag):
    q_perm=[None]*16
    # Uniform-q blocks expose each q label directly; stream recovery is not needed yet.
    for q in range(16):
        byte=(q<<4)|q  # symbol zero
        ranked=unpack_rank_words(encrypt(bytes([byte])*16))
        labels={split_word(word)[0] for word in ranked}
        if len(labels)!=1: raise RuntimeError("uniform q label mismatch")
        q_perm[q]=labels.pop()
    if len(set(q_perm))!=16: raise RuntimeError("q labels are not a permutation")
    q_inv=invert_permutation(q_perm)

    # Two exact-rotation blocks per symbol, then 48 more blocks for symbol zero.
    records=[]
    for n in range(16,48):
        symbol=(n-16)//2
        records.append((n,symbol,encrypt(variable_plaintext(symbol))))
    for n in range(48,QUERIES):
        records.append((n,0,encrypt(variable_plaintext(0))))

    cache=[]
    for n,symbol,ct in records:
        cache.append(recover_variable_block(ct,n,symbol,q_inv,None,(),True))
    candidate_sets=[]
    for symbol in range(16):
        sets=[{k for k,_ in cache[i]} for i,(_,s,_) in enumerate(records) if s==symbol]
        possible=set.intersection(*sets)
        candidate_sets.append(possible)

    def matchings():
        assignment=[None]*16
        def walk(used):
            if all(x is not None for x in assignment):
                yield assignment[:]; return
            s=min((i for i,x in enumerate(assignment) if x is None),
                  key=lambda i:len(candidate_sets[i]-used))
            for k in sorted(candidate_sets[s]-used):
                assignment[s]=k
                yield from walk(used|{k})
                assignment[s]=None
        yield from walk(set())

    selected=None
    for symbol_inv in matchings():
        try:
            sequences=[[] for _ in range(16)]
            for i,(n,symbol,ct) in enumerate(records):
                matches=[item for item in cache[i] if item[0]==symbol_inv[symbol]]
                if len(matches)!=1: raise RuntimeError("ambiguous variable block")
                _,values=matches[0]
                for lane,value in enumerate(values): sequences[lane].append(value)
            nodes,coefficients=recover_model(sequences,offset=16)
            selected=(symbol_inv,nodes,coefficients)
            break
        except RuntimeError:
            continue
    if selected is None: raise RuntimeError("no symbol permutation produced a model")
    symbol_inv,nodes,coefficients=selected
    flag_ct=encrypt_flag()
    streams=folded_stream(nodes,coefficients,len(flag_ct)//32)
    return decrypt_flag(flag_ct,streams,q_perm,symbol_inv)


def remote():
    with socket.create_connection((HOST,PORT),timeout=20) as sock:
        sock.settimeout(20)
        recvuntil(sock,b"> ")
        def encrypt(block):
            sock.sendall(b"1\n")
            recvuntil(sock,b"plaintext hex> ")
            sock.sendall(block.hex().encode()+b"\n")
            response=recvuntil(sock,b"> ")
            m=re.search(rb"ciphertext: ([0-9a-f]{64})",response)
            if not m: raise RuntimeError(response.decode(errors="replace"))
            return bytes.fromhex(m.group(1).decode())
        def encrypt_flag():
            sock.sendall(b"2\n")
            response=recvuntil(sock,b"> ")
            m=re.search(rb"encrypted flag: ([0-9a-f]+)",response)
            if not m: raise RuntimeError(response.decode(errors="replace"))
            return bytes.fromhex(m.group(1).decode())
        return solve_oracle(encrypt,encrypt_flag)


def local_test():
    from sudokrypt_core import SudoKrypt
    expected=b"kaspersky{local_sudokrypt_test_flag}"
    core=SudoKrypt(b"seed",expected,QUERIES,session_nonce=b"0"*16)
    got=solve_oracle(core.encrypt_block,core.encrypt_flag)
    print(got,got==expected)


if __name__ == "__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--local-test",action="store_true")
    args=ap.parse_args()
    result=local_test() if args.local_test else print(remote().decode())

