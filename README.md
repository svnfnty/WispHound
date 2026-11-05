# WispHound

**WPS reconnaissance and Pixie Dust prioritization for Kali Linux.**

WispHound scans for WPS-enabled access points, classifies each one by the
likelihood that its chipset is vulnerable to the **Pixie Dust** offline attack,
and puts the most promising targets at the top of the list — highlighted in
cyan. When you pick a flagged target, WispHound offers to run Pixie Dust first
before falling back to PIN generation or online brute force.

> **Authorized use only.** WPS auditing is a destructive, noisy operation.
> Only run WispHound against networks you own or have explicit written
> permission to test. Unauthorized use is illegal in most jurisdictions.

---

## Features

- **Chipset-aware scanning** — reads WPS `Model`, `Model Number`, and
  `Device name` from `iw scan` output and cross-references them against a
  curated table of chipsets documented as Pixie Dust vulnerable
  (Ralink/MediaTek RT, Realtek RTL8xxx, Broadcom BCM43xx, Atheros AR9xxx).
- **Vulnerability-first sorting** — Pixie-vulnerable APs are sorted to the top
  and highlighted in cyan. WPS-locked APs are red; already-stored APs are
  yellow.
- **Auto-prompt for Pixie Dust** — when you pick a flagged target, WispHound
  asks whether to try Pixie Dust before generating PINs.
- **Robust `pixiewps` parsing** — extracts the PIN from `pixiewps` output even
  when it exits non-zero, and accepts `<empty>` as a valid result.
- **MAC-prefix PIN generation** — the standard `pin24` / `pin28` / `pin32` /
  D-Link / ASUS / Airocon algorithms plus a large table of static vendor PINs.
- **Smart brute force** — two-phase (first half / second half) online attack
  with session save/restore.
- **Credential storage** — optional `-w` writes findings to
  `reports/stored.txt` and `reports/stored.csv`.
- **Loop mode** — `-l` keeps scanning and attacking until you stop it.

---

## Requirements

WispHound is designed for **Kali Linux** (or any Debian/Ubuntu derivative with
`wpa_supplicant` WPS support). You need root privileges to run it.

### System packages

| Package | Purpose |
|---------|---------|
| `python3` (>= 3.6) | Interpreter |
| `python3-wcwidth` | Terminal display-width handling for the network table |
| `wpa_supplicant` (built with `CONFIG_WPS=y`) | WPS registration and PBC |
| `pixiewps` | Offline Pixie Dust PIN recovery |
| `iw` | Wireless scanning |
| `iproute2` | `ip link` interface up/down |
| `wireless-tools` | Optional, for `wext` driver fallback |

Install everything on Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-wcwidth wpa_supplicant pixiewps iw iproute2

