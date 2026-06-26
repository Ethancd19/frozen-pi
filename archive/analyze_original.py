from collections import Counter
import math
from tqdm import tqdm

DUMP_PATH = "dumps/0_sec/dump_20250507_024121.bin"
KEY_LEN = 16

KNOWN_KEYS = [
    bytes.fromhex("00000000000000000000000000000000"),
    bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
]

def load_dump():
    with open(DUMP_PATH, "rb") as f:
        return f.read()

def entropy(b):
    probs = [b.count(x) / len(b) for x in set(b)]
    return -sum(p * math.log2(p) for p in probs)

def is_good_candidate(b):
    if all(x == b[0] for x in b):
        return False
    if all(32 <= x < 126 for x in b):
        return False
    if entropy(b) < 3.5:
        return False
    return True

def find_key_candidates(data, key_len=16):
    print(f"[+] Scanning {len(data)} bytes of memory for repeating {key_len}-byte patterns...")
    counts = Counter()
    for i in tqdm(range(len(data) - key_len), desc="Analyzing"):
        chunk = data[i:i+key_len]
        counts[chunk] += 1
    raw_candidates = [chunk for chunk, count in counts.items() if count > 2]
    filtered = []
    for c in tqdm(raw_candidates, desc="Filtering"):
        if is_good_candidate(c):
            filtered.append(c)
    return filtered

def search_known_keys(candidates, data, threshold=4):
    print("[+] Searching for known test keys...")

    for known in KNOWN_KEYS:
        in_candidates = known in candidates
        in_ram = known in data

        if in_candidates:
            print(f"  [!!] Found in candidates: {known.hex()}")
            continue
        elif in_ram:
            print(f"  [!!] Found in raw RAM, but not in filtered list: {known.hex()}")
            continue
        
        for c in candidates:
            if hamming_distance(known, c) <= threshold:
                print(f"  [~] Near match (<= {threshold} bits off): {c.hex()}")
                print(f"      Hamming distance from {known.hex()}: {hamming_distance(known, c)}")
                break
        else:
            print(f"  [--] Not found (even fuzzy match): {known.hex()}")

def hamming_distance(a, b):
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def main():
    data = load_dump()
    print(f"[+] Loaded {len(data)} bytes from dump.")

    keys = find_key_candidates(data)
    print(f"[+] Found {len(keys)} potential key-like patterns:\n")

    if keys:
        # save_results(keys)
        search_known_keys(keys, data)

if __name__ == "__main__":
    main()