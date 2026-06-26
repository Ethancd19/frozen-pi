from collections import Counter
import math
from tqdm import tqdm

DUMP_PATH = "dumps/dump_20250506_020525.bin"
KEY_LEN = 16
IMAGE_PATH = "test_image_128.raw"
IMAGE_WIDTH = 128
IMAGE_HEIGHT = 128
IMAGE_LEN = IMAGE_WIDTH * IMAGE_HEIGHT * 3  # RGB

# Add as many keys as needed
KNOWN_KEYS = [
    bytes.fromhex("00000000000000000000000000000000"),
    bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    # bytes.fromhex("your_additional_key_here"),
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
    for i in tqdm(range(len(data) - key_len), desc="Analyzing Keys"):
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

def search_for_image(data):
    print("[+] Searching for injected image...")
    try:
        with open(IMAGE_PATH, "rb") as f:
            image_bytes = f.read()
    except FileNotFoundError:
        print("  [--] Image file not found. Skipping image scan.")
        return

    matches = []
    i = 0
    while i < len(data):
        i = data.find(image_bytes[:128], i)  # Use partial match to avoid false negatives
        if i == -1:
            break
        if data[i:i+len(image_bytes)] == image_bytes:
            print(f"  [!!] Exact image found at offset: {hex(i)}")
            matches.append(i)
        i += 1

    if not matches:
        print("  [--] Exact image not found.")
    else:
        for idx, offset in enumerate(matches):
            out_file = f"recovered_images/recovered_image_{idx}.raw"
            with open(out_file, "wb") as out:
                out.write(data[offset:offset+len(image_bytes)])
            print(f"  [+] Extracted match #{idx} to {out_file}")


def hamming_distance(a, b):
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def main():
    data = load_dump()
    print(f"[+] Loaded {len(data)} bytes from dump.")

    keys = find_key_candidates(data)
    print(f"[+] Found {len(keys)} potential key-like patterns:\n")

    if keys:
        search_known_keys(keys, data)

    search_for_image(data)

if __name__ == "__main__":
    main()