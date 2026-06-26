#!/usr/bin/env python3
"""
Frozen Pi: Cold Boot Attack Memory Analysis Tool
Analyzes binary memory dumps for AES key recovery and image reconstruction.

Usage:
    python analyze.py <dump_path> [options]

Examples:
    python3 analyze.py dumps/dump_0sec.bin
    python3 analyze.py dumps/dump_5sec.bin --csv results.csv
    python3 analyze.py dumps/dump_10sec.bin --image test_image_128.raw --original original_image.jpg
    python3 analyze.py dumps/dump_30sec.bin --csv results.csv --image test_image_128.raw --original original_image.jpg
"""

import argparse
import csv
import math
import os
from collections import Counter

from tqdm import tqdm

try:
    import numpy as np
    from PIL import Image
    from skimage.metrics import structural_similarity as ssim
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False
    print("[!] Image processing libraries not found. Image reconstruction features will be disabled.")

# Constants

KEY_LEN = 16
HAMMING_THRESHOLDS = [1, 2]
ENTROPY_THRESHOLD = 3.5
MIN_REPEAT_COUNT = 2

# Well-known NIST AES-128 test vector used in experiments.
# Replace or extend this list if testing with a different key.
KNOWN_KEYS = [
    bytes.fromhex("00000000000000000000000000000000"),
    bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
]

# Core Analysis Functions

def load_dump(path: str) -> bytes:
    """Load a binary memory dump from the specified path."""
    with open(path, "rb") as f:
        data = f.read()
    print(f"[+] Loaded {len(data)} bytes from {path}")
    return data

def entropy(b: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence."""
    if len(b) == 0:
        return 0.0
    probs = [b.count(x) / len(b) for x in set(b)]
    return -sum(p * math.log2(p) for p in probs)

def is_good_candidate(b: bytes) -> bool:
    """
    Filter out low-quality key candidates:
    - All bytes the same
    - All bytes are printable ASCII
    - Entropy below threshold
    """
    if all(x == b[0] for x in b):
        return False
    if all(32 <= x < 126 for x in b):
        return False
    if entropy(b) < ENTROPY_THRESHOLD:
        return False
    return True

def find_key_candidates(data: bytes, key_len: int = KEY_LEN):
    """Scan memory dump for repeating key-length byte patterns and filter them.
    Returns (filtered_candidates, raw_counts)
    """
    print(f"[+] Scanning {len(data)} bytes of memory for repeating {key_len}-byte patterns...")
    counts: Counter = Counter()
    for i in tqdm(range(len(data) - key_len), desc="Scanning"):
        chunk = data[i:i + key_len]
        counts[chunk] += 1
    
    raw_candidates = [chunk for chunk, count in counts.items() if count > MIN_REPEAT_COUNT]
    filtered = [c for c in tqdm(raw_candidates, desc="Filtering") if is_good_candidate(c)]
    print(f"[+] Found {len(filtered)} good candidates out of {len(raw_candidates)} raw candidates.")
    return filtered, counts

def hamming_distance(a: bytes, b: bytes) -> int:
    """Calculate the Hamming distance (number of differing bits) between two byte sequences."""
    assert len(a) == len(b), "Byte sequences must be of equal length"
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def search_known_keys(candidates, counts, data, thresholds=None):
    """
    Search for known AES test keys in the candidates and raw data.
    Returns a list of results with exact and near matches.
    Returns a list of result dictionaries suitable for CSV output.
    """
    if thresholds is None:
        thresholds = HAMMING_THRESHOLDS

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

        row = {
            "key": known.hex(),
            "exact_matches": exact_count,
            **{f"hamming_{t}_bit": n for t, n in zip(thresholds, near_counts)}
        }
        results.append(row)

        if exact_count > 0:
            print(f"  [!!] Found exact match for {known.hex()} in candidates: {exact_count} occurrences")
        else:
            print(f"  [--] No exact match for {known.hex()} in candidates")
            fuzzy = [(t, n) for t, n in zip(thresholds, near_counts) if n > 0]

            if fuzzy:
                print(f"  [~] Near matches for {known.hex()}: " + ", ".join(f"{n} occurrences at {t} bits off" for t, n in fuzzy))
            else:
                print(f"  [--] No near matches for {known.hex()} in candidates")
    return results

def write_csv(results, path: str, thresholds=None):
    """Write the search results to a CSV file."""
    if thresholds is None:
        thresholds = HAMMING_THRESHOLDS

    fieldnames = ["key", "exact_matches"] + [f"hamming_{t}_bit" for t in thresholds]
    with open(path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"[+] Results written to {path}")

# Image Recovery Functions
 
def compare_ssim(img_a, img_b) -> float:
    """Compute SSIM score between two PIL Images."""
    a = np.array(img_a).astype("uint8")
    b = np.array(img_b).astype("uint8")
    score, _ = ssim(a, b, full=True, channel_axis=-1)
    return score
 
 
def search_for_image(data: bytes, image_path: str, original_path: str,
                     output_dir: str = "recovered_images",
                     best_output: str = "rebuilt_images/best_match.png",
                     width: int = 128, height: int = 128):
    """
    Search a memory dump for a known raw RGB image, recover all matches,
    and identify the best match using SSIM against the original.
    """
    if not IMAGE_SUPPORT:
        print("[!] Image recovery requires: numpy, Pillow, scikit-image. Skipping.")
        return
 
    image_size = width * height * 3  # RGB
 
    try:
        with open(image_path, "rb") as f:
            image_bytes = f.read()
    except FileNotFoundError:
        print(f"[!] Image file not found: {image_path}. Skipping image scan.")
        return
 
    try:
        original = Image.open(original_path).resize((width, height))
    except FileNotFoundError:
        print(f"[!] Original image not found: {original_path}. Skipping SSIM comparison.")
        return
 
    print(f"\n[+] Searching for injected image ({image_size} bytes)...")
    matches = []
    i = 0
    while i < len(data):
        i = data.find(image_bytes[:512], i)
        if i == -1:
            break
        if data[i:i + len(image_bytes)] == image_bytes:
            print(f"  [!!] Exact image found at offset: {hex(i)}")
            matches.append(i)
        i += 1
 
    if not matches:
        print("  [--] Image not found in dump.")
        return
 
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.dirname(best_output) or ".", exist_ok=True)
 
    best_score = -1
    best_image = None
    best_index = -1
 
    for idx, offset in enumerate(matches):
        raw_data = data[offset:offset + image_size]
        out_file = os.path.join(output_dir, f"recovered_image_{idx}.raw")
        with open(out_file, "wb") as f:
            f.write(raw_data)
        print(f"  [+] Saved recovered_image_{idx}.raw")
 
        try:
            img = Image.frombytes("RGB", (width, height), raw_data)
            score = compare_ssim(original, img)
            print(f"      SSIM score: {score:.4f}")
            if score > best_score:
                best_score = score
                best_image = img
                best_index = idx
        except Exception as e:
            print(f"      [!] Error: {e}")
 
    if best_image:
        best_image.save(best_output)
        print(f"\n[+] Best match: recovered_image_{best_index}.raw (SSIM {best_score:.4f})")
        print(f"[+] Saved to {best_output}")
 
 
# Entry Point and Argument Parsing
 
def parse_args():
    parser = argparse.ArgumentParser(
        description="Frozen Pi — Cold boot memory dump analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("dump_path", help="Path to binary memory dump file")
    parser.add_argument(
        "--csv", metavar="OUTPUT_CSV",
        help="Write key recovery results to a CSV file"
    )
    parser.add_argument(
        "--image", metavar="RAW_IMAGE",
        help="Path to the known raw RGB image that was injected (enables image recovery)"
    )
    parser.add_argument(
        "--original", metavar="ORIGINAL_IMAGE",
        help="Path to the original image for SSIM comparison (required with --image)"
    )
    parser.add_argument(
        "--image-width", type=int, default=128,
        help="Width of injected image in pixels (default: 128)"
    )
    parser.add_argument(
        "--image-height", type=int, default=128,
        help="Height of injected image in pixels (default: 128)"
    )
    parser.add_argument(
        "--output-dir", default="recovered_images",
        help="Directory to save recovered image fragments (default: recovered_images)"
    )
    parser.add_argument(
        "--best-output", default="rebuilt_images/best_match.png",
        help="Path to save the best recovered image (default: rebuilt_images/best_match.png)"
    )
    return parser.parse_args()
 
 
def main():
    args = parse_args()
 
    # Key recovery
    data = load_dump(args.dump_path)
    candidates, counts = find_key_candidates(data)
    results = search_known_keys(candidates, counts, data)
 
    if args.csv:
        write_csv(results, args.csv)
 
    # Image recovery (optional)
    if args.image:
        if not args.original:
            print("[!] --original is required when using --image")
        else:
            search_for_image(
                data,
                image_path=args.image,
                original_path=args.original,
                output_dir=args.output_dir,
                best_output=args.best_output,
                width=args.image_width,
                height=args.image_height,
            )
 
 
if __name__ == "__main__":
    main()