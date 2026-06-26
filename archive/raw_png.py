import os
from PIL import Image

# Image specs
width, height = 128, 128
image_size = width * height * 3  # for RGB

# Process all recovered raw files
for i in range(308):  # Change range if more/less images
    raw_filename = f"recovered_images/run2/recovered_image_{i}.raw"
    png_filename = f"rebuilt_images/run2/recovered_image_{i}.png"

    # Ensure file exists and is the right size
    if not os.path.exists(raw_filename):
        print(f"[!] Missing: {raw_filename}")
        continue

    with open(raw_filename, "rb") as f:
        data = f.read()

    if len(data) != image_size:
        print(f"[!] Skipping {raw_filename}, unexpected size: {len(data)}")
        continue

    img = Image.frombytes("RGB", (width, height), data)
    img.save(png_filename)
    print(f"[+] Saved: {png_filename}")
