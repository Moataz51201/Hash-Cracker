import hashlib
import pyfiglet
import argparse
import passlib.hash  # For advanced hash algorithms like LM, NTLM, etc.

# Display banner
ascii_banner = pyfiglet.figlet_format("Python 4 Pentesters \nHash Cracker")
print(ascii_banner)

SUPPORTED_HASHES = ["md5", "md4", "md2", "sha1", "sha224", "sha256", "sha384", "sha512", 
                    "ripemd160", "whirlpool", "mysql41", "lm", "ntlm"]

def detect_hash_type(hash_input):
    """ Guess the hash type based on the hash length and format """
    hash_len = len(hash_input)
    
    if hash_len == 32:
        return ["md5", "lm", "ntlm", "mysql41"]
    elif hash_len == 40:
        return ["sha1", "mysql41"]
    elif hash_len == 64:
        return ["sha256", "whirlpool"]
    elif hash_len == 128:
        return ["sha512"]
    elif hash_len == 56:
        return ["sha224"]
    elif hash_len == 96:
        return ["sha384"]
    elif hash_len == 48:
        return ["ripemd160"]
    else:
        return None

def hash_cracker(wordlist, hash_input, verbose):
    """ Attempt to crack the hash with all supported hash algorithms """
    hash_types = detect_hash_type(hash_input)
    
    if not hash_types:
        print("\n[ERROR] Unable to detect hash type based on its length.")
        return
    
    print(f"[INFO] Detected possible hash types: {', '.join(hash_types)}\n")
    
    try:
        with open(wordlist, 'r',encoding='utf-8',errors='ignore') as file:
            for line in file.readlines():
                word = line.strip()

                for hash_type in hash_types:
                    hash_ob = None

                    # Generate the hash based on the detected hash type
                    if hash_type == "md2":
                        hash_ob = hashlib.new('md2', word.encode())
                    elif hash_type == "md4":
                        hash_ob = hashlib.new('md4', word.encode())
                    elif hash_type == "md5":
                        hash_ob = hashlib.md5(word.encode())
                    elif hash_type == "mysql41":
                        hash_ob = hashlib.sha1(hashlib.sha1(word.encode()).digest())
                    elif hash_type == "sha1":
                        hash_ob = hashlib.sha1(word.encode())
                    elif hash_type == "sha224":
                        hash_ob = hashlib.sha224(word.encode())
                    elif hash_type == "sha256":
                        hash_ob = hashlib.sha256(word.encode())
                    elif hash_type == "sha384":
                        hash_ob = hashlib.sha384(word.encode())
                    elif hash_type == "sha512":
                        hash_ob = hashlib.sha512(word.encode())
                    elif hash_type == "ripemd160":
                        hash_ob = hashlib.new('ripemd160', word.encode())
                    elif hash_type == "whirlpool":
                        hash_ob = hashlib.new('whirlpool', word.encode())
                    elif hash_type == "lm":
                        hash_ob = passlib.hash.lmhash.hash(word)
                    elif hash_type == "ntlm":
                        hash_ob = passlib.hash.nthash.hash(word)

                    if hash_ob:
                        hashed_pass = hash_ob.hexdigest() if isinstance(hash_ob, hashlib._hashlib.HASH) else hash_ob

                        
                        if verbose:
                            print(f"Trying password: {word} with {hash_type} | Hash: {hashed_pass}")

                        
                        if hashed_pass.lower() == hash_input.lower():
                            print(f"\n[+] Found cleartext password: {word} (using {hash_type})")
                            return

        print("\n[-] Password not found in the wordlist.")

    except FileNotFoundError:
        print(f"\n[ERROR] Wordlist file '{wordlist}' not found.")
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Multi-Hash Cracker with Auto Detection")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-c", "--hash", required=True, help="Hash to be cracked")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    
    hash_cracker(args.wordlist, args.hash, args.verbose)
