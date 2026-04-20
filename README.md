# DEFCON CTF — Challenge Writeups

**Author:** Hohin.J  
**Event:** DEFCON CTF — April 2026

---

## Table of Contents

  - [🟢 Beginner](#-beginner)
      - [Caesars Emporium](#caesars-emporium)
      - [Agent of Chaos](#agent-of-chaos)
      - [H3h3](#h3h3)
      - [Hidden](#hidden)
  - [🔐 Crypto](#-crypto)
    - [Enjoy Your Meal](#enjoy-your-meal)
    - [Encrypted Artifact](#encrypted-artifact)
  - [⚙️ Reverse Engineering](#️-reverse-engineering)
    - [Basic](#basic)
  - [🔎 Forensics](#-forensics)
    - [Deleted Evidence](#deleted-evidence)
  - [🎲 Misc](#-misc)
    - [Romeo and Juliet](#romeo-and-juliet)

---

### 🟢 Beginner

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

### 🔐 Crypto

---

#### Enjoy Your Meal

> *Cryptography | Easy | 77 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Enjoy Your Meal |
| **Category** | Cryptography |
| **Difficulty** | Easy |
| **Points** | 77 |
| **Author** | quixel200 |
| **Solves** | 69 |
| **Key / Hint** | `thechefsayshi` (given in description) |
| **Flag** | `defcon{3nj0y_y0uR_m341_5p3c1a1ly_m4d3_by_th3_ch3f}` |

##### Challenge Description

The challenge provides a file **meals.txt** containing a long hexadecimal string, and a key in the description: **`thechefsayshi`**.

*"Here's something to start off your meal: thechefsayshi"* — this is the XOR key and a direct hint that the first layer is XOR encryption.

##### Encryption Layers Overview

The file had 6 layers of obfuscation stacked on top of each other:

| # | Layer | Operation | Output Type |
|---|---|---|---|
| 1 | Hex Encoding | Read file as hex string → bytes | Raw binary bytes |
| 2 | XOR Cipher | XOR with key: `thechefsayshi` | Garbled bytes |
| 3 | Base64 Encode | Decode Base64 → hex string | Hex string |
| 4 | Hex Encoding | Decode hex string → bytes | Raw bytes |
| 5 | Base64 Encode | Decode Base64 → Morse-binary text | Morse code text |
| 6 | Morse Binary | `----- = 0`, `.---- = 1` → 8-bit ASCII chars | Plaintext / FLAG |

##### Step 1: Hex Decode the File

Opening **meals.txt** shows a massive hexadecimal string. Convert to raw bytes:

```python
data = open('meals.txt', 'rb').read().strip()
raw = bytes.fromhex(data.decode('ascii'))
# raw = 8460 bytes of binary data
```

##### Step 2: XOR Decrypt with Key `thechefsayshi`

```python
key = b'thechefsayshi'   # 13 bytes, repeating
xored = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))
# Result: a Base64-encoded string
```

After XOR, the output is a valid Base64 string (only A–Z, a–z, 0–9, +, /, = characters).

##### Step 3: Base64 Decode → Hex String

```python
import base64
b64_1 = base64.b64decode(xored)
# Result: another hex string like '4c5330744c533074...'
```

##### Step 4: Hex Decode Again

```python
hex2 = bytes.fromhex(b64_1.decode('ascii'))
# Result: yet more Base64-encoded bytes
```

##### Step 5: Base64 Decode → Morse Code

```python
b64_2 = base64.b64decode(hex2)
morse_text = b64_2.decode('ascii')
```

First few lines of `morse_text`:

```
----- .---- .---- ----- ----- .---- ----- -----
----- .---- .---- ----- ----- .---- ----- .----
----- .---- .---- ----- ----- .---- .---- -----
```

Each line contains exactly **8 groups**, where each group is either `-----` or `.----` — binary encoded in Morse!

##### Step 6: Morse Binary → ASCII

| Morse Group | Binary Digit |
|---|---|
| `-----` | 0 (five dashes = zero) |
| `.----` | 1 (dot-four-dashes = one) |

Each line of 8 Morse groups = one 8-bit binary number = one ASCII character:

```python
lines = morse_text.strip().split('\n')
result = ''
for line in lines:
    groups = line.strip().split(' ')
    bits = ''.join('0' if g in ('-----', '---') else '1' for g in groups)
    if len(bits) == 8:
        result += chr(int(bits, 2))
```

**Example — first line decoded:**

| | |
|---|---|
| **Morse groups** | `----- .---- .---- ----- ----- .---- ----- -----` |
| **Binary bits** | `0 1 1 0 0 1 0 0` |
| **Binary (joined)** | `01100100` |
| **Decimal** | 100 |
| **ASCII char** | `d` |

##### Complete Solve Script

```python
import base64

# Layer 1: Read hex file
data = open('meals.txt', 'rb').read().strip()
raw  = bytes.fromhex(data.decode('ascii'))

# Layer 2: XOR with key
key   = b'thechefsayshi'
xored = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))

# Layer 3+4: Base64 -> hex -> bytes
b64_1 = base64.b64decode(xored)
hex2  = bytes.fromhex(b64_1.decode('ascii'))

# Layer 5: Base64 -> Morse text
b64_2 = base64.b64decode(hex2)
morse = b64_2.decode('ascii')

# Layer 6: Morse binary -> ASCII
result = ''
for line in morse.strip().split('\n'):
    groups = line.strip().split(' ')
    bits = ''.join('0' if g in ('-----', '---') else '1' for g in groups)
    if len(bits) == 8:
        result += chr(int(bits, 2))

print(result)
# defcon{3nj0y_y0uR_m341_5p3c1a1ly_m4d3_by_th3_ch3f}
```

##### Flag

```
defcon{3nj0y_y0uR_m341_5p3c1a1ly_m4d3_by_th3_ch3f}
```

##### Lessons Learned

- **Recognise layer stacking** — CTF crypto challenges frequently chain multiple encodings. When one decoding gives another blob, always check: is this hex? Base64? XOR output?
- **XOR + known key = trivial** — XOR is not encryption when the key is known. It provides zero security.
- **Morse as binary** — Here each Morse group encoded a single binary digit (0 or 1), 8 groups per ASCII character — a creative twist on a classic encoding.
- **Base64 signatures** — Output containing only `[A-Za-z0-9+/=]` with length divisible by 4 is almost certainly Base64.
- **Follow the output format** — Each layer's output hints at the next tool: hex string → hex decode, Base64 string → base64 decode, Morse text → Morse decode.

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
| **Flag** | `defcon{x0r_c4sc4d3_k3y_sch3dul3_r3v3rs3d}` |

##### Challenge Description

*An intercepted binary artifact. The README buried inside describes the format: magic header, salt, key schedule table, ciphertext length, ciphertext — in that order. The key is right there in the file. They thought the format was obscure enough.*

##### Step 1: Initial File Analysis

The challenge provided a single binary file: **xor_artifact.bin** (309 bytes total). Performed a full hex dump to understand its raw structure.

**Hex Dump (first bytes):**

```
0000  4e 52 4c 58 43 01 52 4e 37 82 4d 18 ...   NRLXC.RN7.M.
0100  c0 75 ea 5f 14 49 be 33 29 00 00 00   .u._.I.3)...
010c  53 e7 bf 77 8c 10 8f 39 ae 59 7f de   S..w...9.Y..
```

Key observation: at offset `0x108`, the bytes `29 00 00 00` decode as a 4-byte little-endian integer = **41** — the ciphertext length.

##### Step 2: Parsing the Binary Format

| Section | Description |
|---|---|
| **Magic Header** | First N bytes — starts with `NRLXC` (ASCII printable) |
| **Salt** | Fixed-length random bytes following the header |
| **Key Schedule Table** | The XOR key — embedded in plaintext in the file |
| **Ciphertext Length** | 4 bytes, little-endian integer at offset `0x108` = 41 |
| **Ciphertext** | 41 bytes starting at offset `0x10C` (268 decimal) |

Total bytes: `309 = 264 (pre-section) + 4 (length field) + 41 (ciphertext)`

##### Step 3: Extracting the Ciphertext

Ciphertext (41 bytes) extracted from offset `0x10C` to end of file:

```
53 e7 bf 77 8c 10 8f 39 ae 59 7f de 7e 74 38 da
05 c7 d0 a9 26 d1 fd 44 ab f5 e5 0f 89 1d 3a 03
e1 15 4b 83 35 69 63 81 07
```

##### Step 4: Key Recovery via Brute Force

The XOR key schedule was stored in plaintext in the 264-byte pre-section. Brute-force approach:

- Iterate over every possible `key_start` offset (0 to ~200) within the 264-byte pre-section
- For each `key_start`, try every possible `key_length` (1 byte up to remaining bytes)
- XOR the 41-byte ciphertext against the candidate key (cycling if shorter)
- Check if the result decodes to valid ASCII containing `defcon` with a `{`

##### Python Solve Script

```python
data = open('xor_artifact.bin', 'rb').read()

ciphertext  = data[0x10C : 0x10C + 41]
pre_section = data[:0x108]   # 264 bytes

for key_start in range(0, 200):
    for key_len in range(1, 264 - key_start + 1):
        key = pre_section[key_start : key_start + key_len]
        result = bytes(ciphertext[i] ^ key[i % len(key)]
                       for i in range(len(ciphertext)))
        decoded = result.decode('ascii', errors='ignore')
        if 'defcon' in decoded.lower() and '{' in decoded:
            print(f'key_start={key_start}: {decoded}')
```

##### Step 5: Flag Recovered

Key found at `key_start = 90`, `key_len = 41` (same length as ciphertext — no cycling needed).

##### Flag

```
defcon{x0r_c4sc4d3_k3y_sch3dul3_r3v3rs3d}
```

##### Lessons Learned

- **Never embed the XOR key inside the ciphertext file** — it completely breaks security
- **XOR is not encryption** — XOR with a known/recoverable key provides zero confidentiality
- **Known-plaintext attack** — the flag format `defcon{...}` enabled brute-force in milliseconds
- **Key length = Ciphertext length** — the 41-byte key matched the 41-byte ciphertext, confirming single-pass XOR with no key stretching

---

### ⚙️ Reverse Engineering

---

#### Basic

> *Reverse Engineering | Easy | 84 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Basic |
| **Category** | Reverse Engineering |
| **Difficulty** | Easy |
| **Points** | 84 |
| **Author** | jashwanth |
| **Solves** | 55 |
| **Binary** | `callit` (ELF 64-bit x86-64, not stripped) |
| **Description** | "Dynamic analysis is soooo much better / find the hidden text and wrap it in defcon{...}" |
| **Flag** | `defcon{t4i$_i$_@_r3v_fl@g}` |

##### Step 1: File Identification

```bash
$ file callit
callit: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
        for GNU/Linux 4.4.0, not stripped
```

Key findings:
- **ELF 64-bit** — Linux executable binary
- **Not stripped** — symbol names (function names) are preserved — crucial for RE
- **Dynamically linked** — uses external libraries (libc), can see imports like `write`, `strlen`

##### Step 2: Static Analysis with `strings`

```bash
$ strings callit
n0t_th3_r34l_0n3_try_h4rd3r   <-- DECOY flag string
Error: Null pointer at 0xDEADBEEF
decoy_flag                     <-- symbol name confirms it's a fake
decode                         <-- interesting function name
main
```

The string `n0t_th3_r34l_0n3_try_h4rd3r` is an obvious decoy — the symbol `decoy_flag` in the binary's symbol table confirms it was placed intentionally to mislead. The real flag is constructed at runtime by the `decode` function.

##### Step 3: Dynamic Analysis — Running the Binary

The description says *"Dynamic analysis is soooo much better"* — a direct hint to run it:

```bash
$ ./callit
Error: Null pointer at 0xDEADBEEF
```

It crashes immediately, but that error is **intentional misdirection**. The hidden text was already written to a non-standard file descriptor before the "crash." Disassembly reveals the `write` calls go to **fd = 5** (not stdout=1 or stderr=2).

Redirecting fd 5 to a file reveals the hidden text:

```bash
$ ./callit 5>/tmp/out; cat /tmp/out
t4i$_i$_@_r3v_fl@g
```

##### Step 4: Static Reverse Engineering (Disassembly)

`objdump -d callit` reveals how the flag is constructed. Two functions: **`decode()`** and **`main()`**.

**The `decode()` Function — XOR Decryption:**

The `decode()` function XORs every byte with the constant **`0x2A`** (ASCII asterisk `*`):

```asm
1159 <decode>:
  116d:  mov -0x4(%rbp),%eax    ; i = loop counter
  117a:  movzbl (%rax),%edx    ; load byte from array
  118a:  xor $0x2a,%edx        ; XOR each byte with 0x2A
  118d:  mov %dl,(%rax)        ; write back decrypted byte
  118f:  addl $0x1,-0x4(%rbp)  ; i++
  1199:  jl  116d              ; loop while i < length
```

**The `main()` Function — Encrypted Flag Storage:**

Three encrypted segments are loaded onto the stack using hardcoded immediate values, decoded and written to fd 5:

```asm
11b6: movabs $0x750e43750e431e5e,%rax  ; encrypted segment 1 (8 bytes)
11c0: mov    %rax,-0x10(%rbp)
11c4: movl   $0x1958756a,-0x16(%rbp)  ; encrypted segment 2a (4 bytes)
11cb: movw   $0x755c,-0x12(%rbp)      ; encrypted segment 2b (2 bytes)
11d1: movl   $0x4d6a464c,-0x1a(%rbp)  ; encrypted segment 3 (4 bytes)
11e4: call 1159 <decode>              ; decode seg 1 (8 bytes, XOR 0x2A)
11f5: call 1159 <decode>              ; decode seg 2 (6 bytes, XOR 0x2A)
1206: call 1159 <decode>              ; decode seg 3 (4 bytes, XOR 0x2A)
121c: call write@plt                  ; fd=5, seg1, 8 bytes
1232: call write@plt                  ; fd=5, seg2, 6 bytes
1248: call write@plt                  ; fd=5, seg3, 4 bytes
1273: call write@plt                  ; fd=2, error msg (fake crash)
```

##### Step 5: Manual Decryption (Static Approach)

Each segment is stored as a little-endian integer. XOR each byte with `0x2A`:

| Segment | Encrypted (LE hex) | Raw bytes | XOR 0x2A | Decoded |
|---|---|---|---|---|
| Seg 1 (8 bytes) | `0x750e43750e431e5e` | `5e 1e 43 0e 75 43 0e 75` | `74 34 69 24 5f 69 24 5f` | `t4i$_i$_` |
| Seg 2 (6 bytes) | `0x1958756a` + `0x755c` | `6a 75 58 19 5c 75` | `40 5f 72 33 76 5f` | `@_r3v_` |
| Seg 3 (4 bytes) | `0x4d6a464c` | `4c 46 6a 4d` | `66 6c 40 67` | `fl@g` |

**Python verification:**

```python
import struct

def xor(b): return bytes(x ^ 0x2a for x in b)

seg1 = xor(struct.pack('<Q', 0x750e43750e431e5e))  # -> t4i$_i$_
seg2 = xor(struct.pack('<I', 0x1958756a) +
           struct.pack('<H', 0x755c))               # -> @_r3v_
seg3 = xor(struct.pack('<I', 0x4d6a464c))          # -> fl@g

hidden = seg1 + seg2 + seg3
print('defcon{' + hidden.decode() + '}')
# defcon{t4i$_i$_@_r3v_fl@g}
```

##### Flag

```
defcon{t4i$_i$_@_r3v_fl@g}
```

The flag in leet-speak reads: *"this is a rev flag"* — a self-referential joke from the author.

##### Lessons Learned

- **`strings` is always the first step** — even basic strings analysis revealed the decoy and the `decode` function name
- **Non-standard file descriptors** — hidden output went to fd=5. Always check ALL `write()` calls in disassembly. Shell redirect `5>/tmp/out` exposes it instantly
- **Decoy flags** — the symbol `decoy_flag` and the obvious string were placed to mislead. Always verify a flag before submitting
- **XOR with constant = trivial** — a single-byte XOR key is visible directly in the disassembly (`xor $0x2a,%edx`)
- **Little-endian byte order** — x86-64 stores multi-byte values in little-endian order; unpack correctly to recover the original byte sequence

---

### 🔎 Forensics

---

#### Deleted Evidence

> *Forensics | Easy | 100 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Deleted Evidence |
| **Category** | Forensics |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Author** | NerdsLab |
| **Solves** | 47 |
| **File** | `evidence.img` (1,474,560 bytes = 1.44 MB floppy image) |
| **Key Hint** | Deletion marker is `0xE5` — overwrites first byte of filename only |
| **Flag** | `defcon{d3l3t3d_but_n0t_g0n3_r3c0v3r3d}` |

##### Background: FAT12 File Deletion

When a file is deleted on FAT, **the data is NOT erased**. Only the directory entry is marked with **`0xE5`** in the first byte of the filename. All file contents remain on disk in their original clusters — fully recoverable.

| Field | Value |
|---|---|
| **Filesystem type** | FAT12 (classic 1.44 MB floppy format) |
| **OEM label** | PHANTOM |
| **Volume label** | EVIDENCEDSK |
| **Bytes per sector** | 512 |
| **Sectors per cluster** | 1 |
| **Root entry count** | 224 (max files in root directory) |
| **Data area offset** | `0x4200` (cluster 2 = sector 33) |

##### Step 1: Identify the Disk Image

```bash
$ file evidence.img
evidence.img: DOS/MBR boot sector
```

A 1.44 MB file is the classic size of a FAT12 floppy disk image. Parsing the boot sector confirms FAT12:

```python
data = open('evidence.img', 'rb').read()
bps  = int.from_bytes(data[11:13], 'little')  # 512
nf   = data[16]                                # 2 (two FATs)
spf  = int.from_bytes(data[22:24], 'little')  # 9 sectors per FAT
rec  = int.from_bytes(data[17:19], 'little')  # 224 root entries

root_start = (1 + 2*9) * 512   # = 0x2600
data_start = 0x2600 + 224*32   # = 0x4200
```

##### Step 2: Parse the Root Directory

The root directory starts at offset **`0x2600`**. Each directory entry is exactly 32 bytes. Scanning for active and deleted entries:

```python
for i in range(224):
    entry = data[0x2600 + i*32 : 0x2600 + i*32 + 32]
    if entry[0] == 0x00: break           # end of directory
    if entry[11] == 0x0F: continue       # skip LFN entries
    status  = 'DELETED' if entry[0] == 0xE5 else 'ACTIVE'
    cluster = int.from_bytes(entry[26:28], 'little')
    size    = int.from_bytes(entry[28:32], 'little')
```

**Results — two entries found:**

| Byte[0] | Name | Ext | Attr | Cluster | Size / Status |
|---|---|---|---|---|---|
| `0x52` (R) | README | TXT | 0x20 | 3 | 42 bytes — ACTIVE |
| `0xE5` (❗) | ?ECRETFL | TXT | 0x20 | 5 | 58 bytes — **DELETED** |

The original filename was **SECRETFL.TXT** — the `0xE5` marker replaced only the first character `S`, leaving bytes 1–10 completely intact.

##### Step 3: Locate the Data on Disk

The directory entry tells us the file starts at cluster 5:

```python
def cluster_offset(cluster):
    return data_start + (cluster - 2) * bytes_per_sector

# cluster 4 offset = 0x4200 + (4-2) * 512 = 0x4600
```

| Cluster | Offset | Content | Status |
|---|---|---|---|
| 2 | `0x4200` | (data area start) | Used by filesystem |
| 3 | `0x4400` | README.TXT data | ACTIVE file |
| 4 | `0x4600` | SECRETFL.TXT data | DELETED but data intact |
| 5 | `0x4800` | (cluster chain) | Referenced in dir entry |

##### Step 4: Recover the Deleted File Contents

```python
secret_data = data[0x4600 : 0x4600 + 58]
print(secret_data.decode('ascii'))
```

Output:

```
CLASSIFIED EVIDENCE FILE
Operator: Ph4nt0m_0p3r4tor
Flag: defcon{d3l3t3d_but_n0t_g0n3_r3c0v3r3d}
Status: DELETED
```

##### Alternative: One-Line Recovery

```bash
$ strings evidence.img | grep defcon
Flag: defcon{d3l3t3d_but_n0t_g0n3_r3c0v3r3d}
```

Or with Python:

```python
import re
data = open('evidence.img', 'rb').read()
print(re.search(rb'defcon\{[^}]+\}', data).group().decode())
# defcon{d3l3t3d_but_n0t_g0n3_r3c0v3r3d}
```

##### Flag

```
defcon{d3l3t3d_but_n0t_g0n3_r3c0v3r3d}
```

The flag reads: *"deleted but not gone, recovered"* — a perfect description of exactly what we did.

##### Lessons Learned

- **Deletion ≠ Erasure on FAT** — FAT marks deleted files with `0xE5` on the first filename byte only. Cluster data is completely untouched until overwritten by new data
- **`0xE5` is the deletion marker** — a first byte of `0xE5` in a directory entry means "deleted file — but data still here"
- **Cluster pointer survives** — the starting cluster number (bytes 26–27 of directory entry) is preserved after deletion; you can calculate exactly where on disk the file lives
- **`strings` is often enough** — grep/strings across the raw disk image recovers flags without any filesystem parsing
- **Real forensics tools** — Autopsy, Sleuth Kit (`fls` + `icat`), PhotoRec, and TestDisk automate this exact process for real investigations

---

### 🎲 Misc

---

#### Romeo and Juliet

> *Miscellaneous | Easy | 84 Points*

##### Challenge Information

| Field | Details |
|---|---|
| **Challenge Name** | Romeo and Juliet |
| **Category** | Miscellaneous |
| **Difficulty** | Easy |
| **Points** | 84 |
| **Author** | kira07 |
| **Solves** | 54 |
| **File** | `RomeoAndJuliet.txt` — a play-format script |
| **Description** | "The play begins, and the play ends. But what happened in the middle? Read the script closely — every line has a purpose." |
| **Flag** | `defcon{r34d_7h3_57463_d1r3c710n5}` |

##### Background: Shakespeare Programming Language (SPL)

This challenge uses the **Shakespeare Programming Language (SPL)** — a real esoteric programming language where programs are written as Shakespearean plays. Characters act as **variables**. Dialogue assigns values and performs operations. `"Speak your mind!"` outputs the current variable's value as an ASCII character.

**Value System: Adjectives as Binary Powers**

Each adjective before a noun doubles the value. The noun itself = 1 (2⁰):

| SPL Phrase | Adjective Count | Value |
|---|---|---|
| `a king` | 0 | 1 (2⁰) |
| `a noble king` | 1 | 2 (2¹) |
| `a fair noble king` | 2 | 4 (2²) |
| `a bold fair noble king` | 3 | 8 (2³) |
| `a brave bold fair noble king` | 4 | 16 (2⁴) |
| `a sweet brave bold fair noble king` | 5 | 32 (2⁵) |
| `a gentle sweet brave bold fair noble king` | 6 | 64 (2⁶) |
| `a warm gentle sweet brave bold fair noble king` | 7 | 128 (2⁷) |

##### Step 1: Identify the Language

Reading the script reveals structured patterns disguised as a play:

- **Characters as variables** — Romeo and Juliet are the two variables
- **Three operations only** — assignment, add, subtract
- **Output instruction** — `"Speak your mind!"` → `print(chr(Romeo))`
- **Misdirection in Act I** — Scene I is pure noise; only Scene II matters

##### Step 2: Decode the Operation Syntax

| Statement | Meaning |
|---|---|
| `Thou art the difference between a X and a Y.` | Romeo = value(X) − value(Y) |
| `Thou art the sum of thyself and a X.` | Romeo += value(X) |
| `Thou art the difference between thyself and a X.` | Romeo −= value(X) |
| `Speak your mind!` | `print(chr(Romeo))` |

##### Step 3: Execution Trace (First 6 Outputs)

| Instruction | Operation | Romeo Value | Output |
|---|---|---|---|
| difference between warm(7adj) and sweet(5adj) | 128 − 32 | 96 | — |
| sum of thyself and fair noble(2adj) | +4 | 100 | — |
| Speak your mind! | — | 100 | **`d`** |
| sum of thyself and a king(0adj) | +1 | 101 | — |
| Speak your mind! | — | 101 | **`e`** |
| sum of thyself and a king | +1 | 102 | — |
| Speak your mind! | — | 102 | **`f`** |
| difference between thyself and fair noble(2adj) | −4 | 98 | — |
| sum of thyself and a king | +1 | 99 | — |
| Speak your mind! | — | 99 | **`c`** |
| *(... continues building `{r34d_7h3_57463_d1r3c710n5}`)* | | | |

##### Step 4: Automated Python Solver

```python
import re

text  = open('RomeoAndJuliet.txt').read()
lines = [l.strip() for l in text.split('\n') if l.strip()]

ADJECTIVES = ['warm', 'gentle', 'sweet', 'brave', 'bold', 'fair', 'noble']

def get_value(phrase):
    count = sum(1 for w in phrase.lower().split() if w in ADJECTIVES)
    return 2**count

romeo = 0
output = []
in_scene2 = False

for line in lines:
    if 'Scene II'  in line: in_scene2 = True;  continue
    if 'Scene III' in line: break
    if not in_scene2: continue

    # Absolute assignment: difference between A and B
    m = re.match(r'Thou art the difference between a (.+) and a (.+)\.', line)
    if m: romeo = get_value(m.group(1)) - get_value(m.group(2)); continue

    # Add: sum of thyself and X
    m = re.match(r'Thou art the sum of thyself and a (.+)\.', line)
    if m: romeo += get_value(m.group(1)); continue

    # Subtract: difference between thyself and X
    m = re.match(r'Thou art the difference between thyself and a (.+)\.', line)
    if m: romeo -= get_value(m.group(1)); continue

    if line == 'Speak your mind!': output.append(chr(romeo))

print('defcon{' + ''.join(output).strip('defcon{}') + '}')
# defcon{r34d_7h3_57463_d1r3c710n5}
```

##### Notable Misdirections

- **Scene I (The False Dawn)** — `"Thou art a miserable vile cowardly foul evil pig!"` produces no output. Pure misdirection.
- **Negative adjectives** — `"miserable"`, `"vile"`, `"cowardly"`, `"foul"`, `"evil"` are negative in SPL — they negate the noun value. This line sets Juliet = −1, which is irrelevant since Juliet never speaks after this.
- **Scene loop** — `"Let us return to scene II"` at the end of Scene I is a GOTO that skips Scene I entirely on re-entry — the program only processes Scene II once, then exits at Scene III.

##### Flag

```
defcon{r34d_7h3_57463_d1r3c710n5}
```

The flag in leet-speak: *"read the stage directions"* — a perfect meta-joke. Scene II is titled "The Unread Stage Directions" and the entire flag is encoded as Juliet's dialogue instructions to Romeo.

##### Lessons Learned

- **Recognise esoteric languages** — SPL is a well-known esoteric language; a script formatted as a play with characters doing arithmetic dialogue → look up SPL syntax immediately
- **Every line has a purpose** — the challenge description says exactly this; no line is filler
- **Ignore the misdirection** — Scene I is entirely misdirection; the real computation only happens in Scene II
- **Automate the trace** — manual tracing through 100+ lines is error-prone; a 20-line Python regex parser handles the entire script in milliseconds

---

*DEFCON CTF — All Beginner Challenges Solved*
