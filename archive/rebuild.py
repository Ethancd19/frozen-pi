import numpy as np
from PIL import Image
import os
from skimage.metrics import structural_similarity as ssim

# === Settings ===
width, height = 128, 128
image_size = width * height * 3  # for RGB
recovered_dir = "recovered_images/"
original_image_path = "original_image.jpg"
output_path = "rebuilt_images/best_match.png"
num_images = 308

def load_raw_as_image(path, width, height):
    with open(path, "rb") as f:
        raw_data = f.read()
    img = Image.frombytes("RGB", (width, height), raw_data)
    return img

def compare_ssim(imgA, imgB):
    a = np.array(imgA).astype("uint8")
    b = np.array(imgB).astype("uint8")
    ssim_score, _ = ssim(a, b, full=True, channel_axis=-1)
    return ssim_score

original = Image.open("original_image.jpg").resize((width, height))

best_score = -1
best_match = None
best_image = None

for i in range(num_images):
    raw_path = os.path.join(recovered_dir, f"recovered_image_{i}.raw")
    if not os.path.exists(raw_path):
        print(f"[!] Missing: {raw_path}")
        continue

    img = load_raw_as_image(raw_path, width, height)
    score = compare_ssim(original, img)
    print(f"[{i}] SSIM score: {score:.4f}")

    if score > best_score:
        best_score = score
        best_match = i
        best_image = img

# === Save the best match as PNG ===
if best_image:
    best_image.save(output_path)
    print(f"\n[+] Best match: recovered_image_{best_match}.raw with SSIM {best_score:.4f}")
    print(f"[+] Saved best match to {output_path}")
else:
    print("[-] No valid images found.")