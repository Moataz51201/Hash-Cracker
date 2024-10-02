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

## Prerequisites:
- Python 3.x
- 'pyfiglet' for ASCII banners: 'pip install pyfiglet'
- 'passlib' for NTLM and LM hashes: 'pip install passlib'

## How to Use:
1. Install the necessary libraries:
   pip install pyfiglet passlib
