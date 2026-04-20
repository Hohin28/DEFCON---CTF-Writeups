# DEFCON CTF — Challenge Writeups

**Author:** Hohin.J  
**Event:** DEFCON CTF — April 2026

---

## Table of Contents

- [🟢 Beginner](#-beginner)
  - [🔐 Crypto](#-crypto)
    - [Encrypted Artifact](#encrypted-artifact)
    - [Caesars Emporium](#caesars-emporium)
  - [⚙️ Reverse Engineering](#️-reverse-engineering)
    - [Agent of Chaos](#agent-of-chaos)
  - [🔎 Forensics](#-forensics)
    - [H3h3](#h3h3)
  - [🎲 Misc](#-misc)
    - [Hidden](#hidden)

---

## 🟢 Beginner

---

### 🔐 Crypto

---

#### Encrypted Artifact

> *Crypto | Easy | 87 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Encrypted Artifact |
| **Category** | Crypto |
| **Difficulty** | Easy |
| **Points** | 87 |
| **Author** | NerdsLab |
| **Solves** | 50 |
| **Flag Format** | `defcon{...}` |

##### Challenge Description

*An intercepted binary artifact. The README buried inside describes the format: magic header, salt, key schedule table, ciphertext length, ciphertext — in that order. The key is right there in the file. They thought the format was obscure enough.*

##### Challenge Analysis

The challenge provides a single binary file: `xor_artifact.bin` (309 bytes total). The file embeds its own XOR key schedule in plaintext within the pre-section — the encryption key is literally inside the file.

**Key Observations:**
- At offset `0x108`, bytes `29 00 00 00` decode as a little-endian 4-byte integer = **41** (ciphertext length)
- The 264-byte pre-section contains: magic header + salt + key schedule table
- The XOR key is stored in plaintext — a critical security flaw

##### Step 1: Initial File Analysis

Performed a full hex dump of the file to understand its raw structure.

```
0000  4e 52 4c 58 43 01 52 4e 37 82 4d 18 ...   NRLXC.RN7.M.
0100  c0 75 ea 5f 14 49 be 33 29 00 00 00   .u._.I.3)...
010c  53 e7 bf 77 8c 10 8f 39 ae 59 7f de   S..w...9.Y..
```

##### Step 2: Parsing the Binary Format

| Section | Description |
|---|---|
| **Magic Header** | First N bytes — starts with `NRLXC` (ASCII) |
| **Salt** | Fixed-length random bytes following the header |
| **Key Schedule Table** | The XOR key — embedded in plaintext |
| **Ciphertext Length** | 4 bytes, little-endian at offset `0x108` = 41 |
| **Ciphertext** | 41 bytes starting at offset `0x10C` |

Total: `309 = 264 (pre-section) + 4 (length field) + 41 (ciphertext)`

##### Step 3: Extracting the Ciphertext

```
53 e7 bf 77 8c 10 8f 39 ae 59 7f de 7e 74 38 da
05 c7 d0 a9 26 d1 fd 44 ab f5 e5 0f 89 1d 3a 03
e1 15 4b 83 35 69 63 81 07
```

##### Step 4: Key Recovery via Brute Force

Since the XOR key was stored in plaintext in the 264-byte pre-section, a brute-force approach was used — iterating over every possible `key_start` and `key_length`, XORing the ciphertext, and checking for `defcon{` in the result.

##### Solver Script

```python
data = open('xor_artifact.bin', 'rb').read()

ciphertext = data[0x10C : 0x10C + 41]
pre_section = data[:0x108]

for key_start in range(0, 200):
    for key_len in range(1, 264 - key_start + 1):
        key = pre_section[key_start : key_start + key_len]
        result = bytes(ciphertext[i] ^ key[i % len(key)]
                       for i in range(len(ciphertext)))
        decoded = result.decode('ascii', errors='ignore')
        if 'defcon' in decoded.lower() and '{' in decoded:
            print(f'key_start={key_start}: {decoded}')
```

Key found at `key_start=90`, `key_len=41`.

##### Flag

```
defcon{x0r_c4sc4d3_k3y_sch3dul3_r3v3rs3d}
```

##### Lessons Learned

- Never embed the XOR key inside the ciphertext file — it completely breaks security
- XOR is not encryption — with a recoverable key it provides zero confidentiality
- Known-plaintext attack — the flag format enabled brute-force in milliseconds
- Key length = Ciphertext length — confirming single-pass XOR with no key stretching

---

#### Caesars Emporium

> *Crypto | Easy | 50 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Caesars Emporium |
| **Category** | Crypto |
| **Difficulty** | Easy |
| **Points** | 50 |
| **Author** | shreyanth |
| **Solves** | 104 |
| **Flag Format** | `DEFCON{...}` |

##### Challenge Description

*`T1BRTlpZe040UERMQ19PMEhZfQ==`*

Two layers of encryption. The first is a cipher, our favorite. Second is an encoding. The clue to the cipher's special number is this:

> *I am the "unholy" guest, squeezed between the divine. I am the final hour before the world ends, the coldest warning on the clock. I look like a pair of pale legs or the bars of a cage you cannot flee.*

##### Challenge Analysis

Two layers to reverse (in order): **Caesar cipher → Base64 encode**. To solve: Base64 decode first, then undo Caesar.

The riddle clues all point to the Caesar shift value = **11**:

| Clue | Interpretation |
|---|---|
| Final hour before the world ends | Doomsday = midnight; one hour before = **11** o'clock |
| Coldest warning on the clock | The **11th** hour = last warning before disaster |
| Pair of pale legs / bars of a cage | Visual: `11` looks like two vertical bars `││` |

##### Step 1: Base64 Decode

```
Input:   T1BRTlpZe040UERMQ19PMEhZfQ==
Output:  OPQNZY{N4PDLC_O0HY}
```

The decoded text is flag-shaped with shifted letters — confirming Caesar cipher.

##### Step 2: Reverse Caesar Cipher (Shift = 11)

```python
import base64

ct = 'T1BRTlpZe040UERMQ19PMEhZfQ=='
decoded = base64.b64decode(ct).decode('latin-1')

shift = 11
flag = ''
for c in decoded:
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        flag += chr((ord(c) - base - shift) % 26 + base)
    else:
        flag += c  # keep digits, {, }, _ unchanged

print(flag)  # DEFCON{C4ESAR_D0WN}
```

##### Flag

```
DEFCON{C4ESAR_D0WN}
```

##### Lessons Learned

- Layer order matters — cipher first, then encoding; reverse in the opposite order
- Base64 is not encryption — `==` padding immediately signals it
- Caesar cipher has only 25 possible shifts; brute-force takes milliseconds
- CTF riddles often embed the key inside wordplay — visual and verbal clues both count

---

### ⚙️ Reverse Engineering

---

#### Agent of Chaos

> *Beginner | Easy | 79 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Agent of Chaos |
| **Category** | Beginner / Web |
| **Difficulty** | Easy |
| **Points** | 79 |
| **Author** | shreyanth |
| **Solves** | 64 |
| **URL** | https://beginner.labs.nerdslab.in/agentofchaos/ |
| **Flag Format** | `defcon{...}` |

##### Challenge Description

*"Welcome to Aether Systems. Our internal infrastructure is managed through a proprietary browser utility. If you are not using our authorized tools, you will be denied access to the terminal."*

##### Challenge Analysis

The challenge name **"Agent of Chaos"** is a direct clue — in HTTP, **"User-Agent"** is the standard header name. The phrase "proprietary browser utility" means the server expects a specific non-standard User-Agent to grant access.

##### Step 1: Visit the URL — Get Denied

Navigating normally shows an access-denied message. Viewing page source reveals:

```
Access Denied.
Your agent: Mozilla/5.0 (Windows NT 10.0...) -- UNAUTHORIZED
Authorized agent: AetherBrowser/1.0
```

##### Step 2: Spoof the User-Agent

**Method A — curl (fastest):**

```bash
curl -A "AetherBrowser/1.0" https://beginner.labs.nerdslab.in/agentofchaos/
```

**Method B — Python requests:**

```python
import requests

url = 'https://beginner.labs.nerdslab.in/agentofchaos/'
headers = {'User-Agent': 'AetherBrowser/1.0'}
r = requests.get(url, headers=headers)
print(r.text)
```

##### Step 3: Flag Received

```
HTTP/1.1 200 OK
Welcome, Aether Systems operative.
Your access token: defcon{us3r_4g3nt_sp00f3d}
```

##### Flag

```
defcon{us3r_4g3nt_sp00f3d}
```

##### Lessons Learned

- "Agent" in the challenge name directly refers to User-Agent — read descriptions carefully
- User-Agent is client-controlled; servers cannot verify which browser you actually use
- UA-based access control is security by obscurity — not real security
- `curl -A` solves this in under 5 seconds; always check page source for the expected value

---

### 🔎 Forensics

---

#### H3h3

> *Forensics / Steganography | Easy | 50 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | H3h3 |
| **Category** | Forensics |
| **Difficulty** | Easy |
| **Points** | 50 |
| **Author** | minato500 |
| **Solves** | 103 |
| **Flag Format** | `defcon{...}` |

##### Challenge Description

*"someone corrupted my image :("*

##### Challenge Analysis

The file `h3h3.jpg` has a corrupted magic header. A valid JPEG must begin with `FF D8` — instead, the first 12 bytes were all `FF`. Everything from byte 12 onward was intact.

| | Bytes 0–11 |
|---|---|
| **Valid JPEG (JFIF)** | `FF D8 FF E0 00 10 4A 46 49 46 00 01` |
| **Corrupted file** | `FF FF FF FF FF FF FF FF FF FF FF FF` |

##### Step 1: Inspect the Magic Bytes

```python
data = open('h3h3.jpg', 'rb').read()
print(data[:12].hex())
# Output: ffffffffffffffffffff ffff  ← corrupted!
```

##### Step 2: Restore the JPEG Header

```python
data = open('h3h3.jpg', 'rb').read()

jfif_header = bytes([
    0xFF, 0xD8,        # SOI  - Start of Image
    0xFF, 0xE0,        # APP0 - JFIF marker
    0x00, 0x10,        # APP0 length = 16 bytes
    0x4A, 0x46,        # 'JF'
    0x49, 0x46,        # 'IF'
    0x00, 0x01         # null terminator + version
])

fixed = jfif_header + data[12:]
open('fixed_h3h3.jpg', 'wb').write(fixed)
```

##### Step 3: Open and Read the Flag

Opening `fixed_h3h3.jpg` reveals the flag written in plain text at the top of the image.

##### Flag

```
defcon{m4g1c_byt3_h4s_b33n_c0rrupt3d}
```

##### Lessons Learned

- Magic bytes are critical — JPEG = `FF D8`, PNG = `89 50 4E 47`, PDF = `25 50 44 46`
- Partial corruption is easy to fix — only the header was overwritten; data from byte 12 was intact
- Always inspect raw hex before assuming a file is truly broken
- The flag itself is a meta-reference: "magic byte has been corrupted" in leet-speak

---

### 🎲 Misc

---

#### Hidden

> *Misc | Easy | 50 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Hidden |
| **Category** | Misc |
| **Difficulty** | Easy |
| **Points** | 50 |
| **Author** | minato500 |
| **Files** | `challenge.txt` |
| **Flag Format** | `defcon{...}` |

##### Challenge Description

*"you can't see the flag? well that's too bad for you"*

##### Challenge Analysis

The file `challenge.txt` appeared to contain normal Naruto-themed text with no visible flag. The title "hidden" and description hint at **whitespace steganography** — data concealed using invisible space (`0x20`) and tab (`0x09`) characters.

##### Step 1: Inspect Raw File

Using PowerShell to view hex reveals a pattern of `20` (space) and `09` (tab) — not random, but deliberate binary encoding.

```powershell
Get-Content "$HOME\Downloads\challenge.txt" -Raw | Format-Hex
# 00000000  20 09 09 20 20 09 20 20 09 20 09 20 09 09 20 20 09 09...
```

##### Step 2: Identify the Encoding

- `0x20` (Space) = binary `0`
- `0x09` (Tab) = binary `1`
- 8 bits per ASCII character

##### Step 3: Decode with Python

```python
with open('challenge.txt', 'r') as f:
    lines = f.readlines()

# Extract lines containing only whitespace
whitespace_lines = []
for line in lines:
    stripped = line.rstrip('\n\r')
    if stripped and all(c in ' \t' for c in stripped):
        whitespace_lines.append(stripped)

print(f"[+] Found {len(whitespace_lines)} encoded lines")

# Decode: tab=1, space=0
binary_string = ""
for line in whitespace_lines:
    for char in line:
        if char == '\t':
            binary_string += '1'
        elif char == ' ':
            binary_string += '0'

# Convert binary to ASCII
decoded_message = ""
for i in range(0, len(binary_string), 8):
    byte = binary_string[i:i+8]
    if len(byte) == 8:
        decoded_message += chr(int(byte, 2))

print(f"[+] Flag: {decoded_message}")
```

##### Step 4: Output

```
[+] Found 3 whitespace-encoded lines
[+] Binary string length: 352 bits
[+] Flag: defcon{s3cr3t5_4r3_h1dd3n_1n_th3_wh1t3sp4c3}
```

##### Flag

```
defcon{s3cr3t5_4r3_h1dd3n_1n_th3_wh1t3sp4c3}
```

##### Lessons Learned

- Always check for hidden data — hex editors reveal non-printable characters invisible to the eye
- Whitespace steganography is common in CTFs — tabs and spaces encode binary data invisibly
- Challenge hints matter — "hidden" and "you can't see" strongly pointed to invisible characters
- Tab=1, Space=0 with 8 bits per ASCII character is the standard whitespace encoding convention

---

*DEFCON CTF — All Beginner Challenges Solved*
