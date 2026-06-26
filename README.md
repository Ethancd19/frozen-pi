# Frozen Pi: Cold Boot Attacks on Embedded ARM Systems

A reproducible research framework for investigating cold boot attacks on the Raspberry Pi 4 Model B (ARM/LPDDR4). This project demonstrates that AES-128 cryptographic keys remain recoverable from DRAM seconds after a forced power loss, even on embedded systems with soldered, non-removable memory.

> **Research paper:** [Frozen Pi: Investigating Cold Boot Attacks on Embedded Systems](frozen_pi_paper.pdf)

---

## Overview

Cold boot attacks exploit DRAM data remanence (the physical property where memory cells retain their charge briefly after power is lost), by cooling the DRAM and forcing an abrupt shutdown, an attacker can recover sensitive data (cryptographic keys, credentials) from a device they have physical access to.

Unlike traditional x86 cold boot attacks where DIMMs can be removed and transferred to another machine, the Raspberry Pi's LPDDR4 is soldered directly to the board. This project develops a lightweight, hardware-modification-free approach to demonstrate the attack is still feasible.

**Key Findings:**

- AES-128 keys injected into a 16 MB DRAM region remained recoverable up to 60 seconds after power loss
- Cooling with an inverted compressed air canister (~-50°C) significantly extends data persistence
- Physical memory fragmentation reduces recovery rates below theoretical maximums
- Entropy filtering and Hamming-distance scoring reliably identify partially degraded keys

---

## Repository Structure

```text
frozen-pi/
├── hold_key.c              # Floods 16 MB heap region with repeated AES-128 key
├── dump.c                  # Reads physical memory range from /dev/mem at boot
├── virtual_to_physical.c  # Translates virtual addresses to physical via /proc/pagemap
├── analyze.py              # Memory dump analysis: key recovery + image reconstruction
├── requirements.txt        # Python dependencies
├── key_recovery_summary.csv  # Experimental results summary
├── results_summary.csv       # Full results across all power-off intervals
├── original_image.jpg        # Original image used in image injection experiments
├── recovered_image.png       # Best recovered image from dump analysis
├── test_image_128.raw        # 128x128 raw RGB test image used for injection
├── test_image_256.raw        # 256x256 raw RGB test image used for injection
├── rebuilt_images/
│   └── best_match.png        # Best SSIM match recovered from memory dump
├── archive/                  # Earlier versions of analysis scripts
└── frozen_pi_paper.pdf       # Full research paper (IEEE format)
```

---

## Hardware Requirements

- Raspberry Pi 4 Model B (4 GB recommended)
- MicroSD card
- Inverted compressed air canister (for cooling DRAM to ~-50°C)
- Jumper wire (to disconnect GPIO GND pin 6 for forced shutdown)
- Secondary machine for analysis

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Ethancd19/frozen-pi.git
cd frozen-pi
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Compile the C tools on the Raspberry Pi

```bash
gcc -O2 -o hold_key hold_key.c
gcc -O2 -o dump dump.c
gcc -O2 -o virtual_to_physical virtual_to_physical.c
```

## Running the Attack

### Step 1: Inject the AES key into DRAM

Run `hold_key` on the Raspberry Pi. It allocates a 16 MB heap buffer, floods it with ~1 million copies of the test AES-128 key, and prints the virtual address range and PID.

```bash
sudo ./hold_key
# [+] Injected AES key to heap
# [+] PID: 1234
# [+] key_blob address: 0x7f8a000000 - 0x7f8b000000
```

### Step 2: Translate virtual address to physical

In a separate terminal, use the PID and virtual address from Step 1:

```bash
sudo ./virtual_to_physical <PID> <virtual_address>
# [+] Virtual Range : 0x7f8a000000 - 0x7f8b000000
# [+] Physical Range: 0x1a000000 - 0x1b000000
# [+] Written to /boot/key_range.txt
```

This writes the physical address range to `/boot/key_range.txt`, which `dump.c` reads at boot.

### Step 3: Configure dump to run at boot

Add the following to `/etc/rc.local` on the Raspberry Pi (before `exit 0`):

```bash
sudo /path/to/dump
```

`dump.c` reads the physical range from `/boot/key_range.txt` and writes a timestamped binary dump to `/boot/dump_YYYYMMDD_HHMMSS.bin`.

### Step 4: Perform the cold boot attack

1. Spray the DRAM with an inverted compressed air canister for 5-10 seconds
2. Disconnect the GND wire from GPIO header pin 6 (forced shutdown)
3. Note the time of power loss
4. Reconnect power: the Pi will reboot and automatically dump memory
5. Transfer the dump file to your analysis machine via SCP or SD card

### Step 5: Analyze the dump

```bash
# Basic key recovery
python3 analyze.py dumps/dump_0sec.bin

# Key recovery with CSV output
python3 analyze.py dumps/dump_5sec.bin --csv results_5sec.csv

# Key recovery + image reconstruction
python3 analyze.py dumps/dump_10sec.bin \
    --image test_image_128.raw \
    --original original_image.jpg \
    --csv results_10sec.csv
```

---

## Analysis Tool Usage

```text

usage: analyze.py [-h] [--csv OUTPUT_CSV] [--image RAW_IMAGE]
                  [--original ORIGINAL_IMAGE] [--image-width IMAGE_WIDTH]
                  [--image-height IMAGE_HEIGHT] [--output-dir OUTPUT_DIR]
                  [--best-output BEST_OUTPUT]
                  dump_path

positional arguments:
  dump_path             Path to binary memory dump file

options:
  --csv OUTPUT_CSV      Write key recovery results to a CSV file
  --image RAW_IMAGE     Path to injected raw RGB image (enables image recovery)
  --original ORIGINAL_IMAGE
                        Path to original image for SSIM comparison
  --image-width         Width of injected image in pixels (default: 128)
  --image-height        Height of injected image in pixels (default: 128)
  --output-dir          Directory for recovered image fragments (default: recovered_images)
  --best-output         Path for best recovered image (default: rebuilt_images/best_match.png)
```

---

## Results

Key recovery rates across controlled power-off intervals:

| Power Loss | Exact Matches | ≤1 Bit Off | ≤2 Bits Off |
| ---------- | ------------- | ---------- | ----------- |
| 0 sec      | 168,756       | 0          | 0           |
| 5 sec      | 58,368        | 4          | 30          |
| 10 sec     | 2,033         | 8          | 25          |
| 30 sec     | 987           | 3          | 7           |
| 60 sec     | 150           | 0          | 2           |

Recovery drops steeply between 0 and 10 seconds, then plateaus. Lower temperatures extend this window significantly.

---

## Defenses

- **Boot-time memory wiping:** Configure the bootloader to scrub RAM at startup
- **Encrypted RAM / Secure Elements:** Use TPM or hardware memory encryption
- **Minimize key residency:** Derive keys on demand rather than holding them in RAM
- **Physical tamper detection:** Hardware sensors that trigger a memory wipe on tampering
- **Physical access controls:** The most effective mitigation is preventing physical access entirely

---

## Limitations

- Page mapping via `/proc/pagemap` may not capture all 16 MB pages accurately
- Manual stopwatch timing introduces variation; future work should automate via GPIO triggers
- Keys were injected in a uniform bulk pattern rather than distributed across typical cryptographic library memory regions
- Results may vary across Pi hardware revisions and OS versions

---

## Citation

If you use this work, please cite:

```text
Duval, E. (2025). Frozen Pi: Investigating Cold Boot Attacks on Embedded Systems.
Virginia Polytechnic Institute and State University.
```

## References

1. Halderman, J. A., et al. "Lest we remember: cold-boot attacks on encryption keys." _Communications of the ACM_, 52(5), 2009.
2. Heninger, N. & Feldman, A. aeskeyfind. [https://salsa.debian.org/pkg-security-team/aeskeyfind](https://salsa.debian.org/pkg-security-team/aeskeyfind)
3. Won, Y. & Bhasin, S. "Are cold boot attacks still feasible: A case study on raspberry pi with stacked memory." _FDTC 2021_.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
