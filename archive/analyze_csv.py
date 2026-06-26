from collections import Counter
import math
from tqdm import tqdm
import csv

DUMP_PATH = "dumps/5_sec/overdump_20250507_041315.bin"
KEY_LEN = 16
HAMMING_THRESHOLDS = [1, 2]

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
    print(f"[+] Scanning {len(data)} bytes for {key_len}-byte repeating patterns...")
    counts = Counter()
    for i in tqdm(range(len(data) - key_len + 1), desc="Analyzing"):
        chunk = data[i:i+key_len]
        counts[chunk] += 1
    raw_candidates = [chunk for chunk, count in counts.items() if count > 2]
    filtered = [c for c in tqdm(raw_candidates, desc="Filtering") if is_good_candidate(c)]
    return filtered, counts

def hamming_distance(a, b):
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def search_known_keys(candidates, counts, data, thresholds=[1, 2]):
    print("[+] Searching for known test keys...")
    results = []

    for known in KNOWN_KEYS:
        exact_count = counts[known]
        near_counts = [0] * len(thresholds)

        for c in candidates:
            dist = hamming_distance(known, c)
            for i, t in enumerate(thresholds):
                if dist == t:
                    near_counts[i] += counts[c]

        results.append({
            "key": known.hex(),
            "exact_matches": exact_count,
            **{f"near_{t}_bit": n for t, n in zip(thresholds, near_counts)}
        })

    return results

def write_results_csv(results, filename="key_recovery_summary.csv"):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["key", "exact_matches"] + [f"near_{t}_bit" for t in HAMMING_THRESHOLDS]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"[+] Results written to {filename}")

def main():
    data = load_dump()
    print(f"[+] Loaded {len(data)} bytes from dump.")
    candidates, counts = find_key_candidates(data)
    print(f"[+] Found {len(candidates)} filtered key-like patterns.\n")

    results = search_known_keys(candidates, counts, data)
    for res in results:
        print(res)

    write_results_csv(results)

if __name__ == "__main__":
    main()
