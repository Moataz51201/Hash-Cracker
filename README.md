# Hash Cracker

This Python script attempts to crack various types of cryptographic hashes using a wordlist. The script supports multiple hash types, including MD5, SHA1, SHA256, NTLM, and more.

## Features:
- Auto-detection of hash type based on the input hash length.
- Supports common hash algorithms: MD5, SHA1, SHA256, NTLM, LM, and more.
- Wordlist-based cracking.
- Verbose mode to print all attempts.

## Supported Hashes:
- MD5, MD4, MD2
- SHA1, SHA224, SHA256, SHA384, SHA512
- NTLM, LM
- RIPEMD160, Whirlpool
- MySQL41

## Disclaimer:
This script is intended for educational and ethical purposes only. Do not use it to crack passwords or hashes you do not own or have permission to test. The author is not responsible for any misuse of this script.

## Prerequisites:
- Python 3.x
- 'pyfiglet' for ASCII banners: 'pip install pyfiglet'
- 'passlib' for NTLM and LM hashes: 'pip install passlib'

## How to Use:
python hash_cracker.py -w <path_to_wordlist> -c <hash> [-v]
-w: Path to the wordlist file.
-c: Hash to be cracked.
-v: Verbose mode (optional).

## Example:
python3 hash_cracker.py -w wordlist.txt -c 5d41402abc4b2a76b9719d911017c592 -v
