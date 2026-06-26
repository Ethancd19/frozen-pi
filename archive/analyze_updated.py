from collections import Counter
import math
from tqdm import tqdm
import numpy as np
from PIL import Image
import os
from skimage.metrics import structural_similarity as ssim

DUMP_PATH = "dumps/dump_20250506_023216.bin"
KEY_LEN = 16
IMAGE_PATH = "test_image_128.raw"
ORIGINAL_IMAGE = "original_image.jpg"
IMAGE_WIDTH = 128
IMAGE_HEIGHT = 128
IMAGE_LEN = IMAGE_WIDTH * IMAGE_HEIGHT * 3  # RGB
OUTPUT_PNG = "rebuilt_images/best_match.png"
REBUILD_DIR = "recovered_images/"

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

def compare_ssim(imgA, imgB):
    a = np.array(imgA).astype("uint8")
    b = np.array(imgB).astype("uint8")
    ssim_score, _ = ssim(a, b, full=True, channel_axis=-1)
    return ssim_score

def search_for_image(data):
    print("[+] Searching for injected image...")

    try:
        with open(IMAGE_PATH, "rb") as f:
            image_bytes = f.read()
    except FileNotFoundError:
        print("  [--] Image file not found. Skipping image scan.")
        return

    try:
        original_image = Image.open(ORIGINAL_IMAGE).resize((IMAGE_WIDTH, IMAGE_HEIGHT))
    except FileNotFoundError:
        print("  [--] Original image file not found. Skipping SSIM comparison.")
        return
    
    matches = []
    i = 0
    while i < len(data):
        i = data.find(image_bytes[:512], i)  # Use partial match to avoid false negatives
        if i == -1:
            break
        if data[i:i+len(image_bytes)] == image_bytes:
            print(f"  [!!] Exact image found at offset: {hex(i)}")
            matches.append(i)
        i += 1

    if not matches:
        print("  [--] Exact image not found.")
    
    best_score = -1
    best_image = None
    best_index = -1

    os.makedirs(REBUILD_DIR, exist_ok=True)

    for idx, offset in enumerate(matches):
        out_file = f"{REBUILD_DIR}/recovered_image_{idx}.raw"
        raw_data = data[offset:offset + len(image_bytes)]
        with open(out_file, "wb") as out:
            out.write(raw_data)
        print(f"  [+] Recovered image #{idx} saved to {out_file}")

        try: 
            img = Image.frombytes("RGB", (IMAGE_WIDTH, IMAGE_HEIGHT), raw_data)
            score = compare_ssim(original_image, img)
            print(f"  [{idx}] SSIM score: {score:.4f}")
            if score > best_score:
                best_score = score
                best_image = img
                best_index = idx
        except Exception as e:
            print(f"    [--] Error processing image: {e}")
    if best_image:
        os.makedirs(os.path.dirname(OUTPUT_PNG), exist_ok=True)
        best_image.save(OUTPUT_PNG)
        print(f"\n[+] Best match: recovered_image_{best_index}.raw with SSIM {best_score:.4f}")
        print(f"[+] Saved best match to {OUTPUT_PNG}")
    else:
        print("[-] No valid images found.")


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
