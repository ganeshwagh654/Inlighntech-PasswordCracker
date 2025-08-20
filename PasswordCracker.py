import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

hash_name = [
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'sha512'
]

def generate_passwords(min_length, max_length, characters):
    for length in range(min_length, max_length + 1):
        for pwd in itertools.product(characters, repeat=length):
            yield ''.join(pwd)

def check_hash(hash_fn, password, target_hash):
    return hash_fn(password.encode()).hexdigest() == target_hash

def crack_hash(target_hash, wordlist=None, hash_type='md5', min_length=0, max_length=0, characters=string.ascii_letters + string.digits, max_workers=4):
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None or hash_type not in hash_name:
        raise ValueError(f'[!] Invalid hash type: {hash_type}. Supported types: {hash_name}')

    if wordlist:
        with open(wordlist, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            total_lines = len(lines)
            print(f"[*] Cracking hash {target_hash} using {hash_type} with a list of {total_lines} passwords.")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(check_hash, hash_fn, line.strip(), target_hash): line for line in lines}
                for future in tqdm(futures, total=total_lines, desc="Cracking hash"):
                    if future.result():
                        return futures[future].strip()
    elif min_length > 0 and max_length > 0:
        total_combinations = sum(len(characters) ** length for length in range(min_length, max_length + 1))
        print(f'[*] Cracking hash {target_hash} using {hash_type} with generated passwords of length {min_length}-{max_length}. Total combinations: {total_combinations}.')

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=total_combinations, desc='Generating and cracking hash') as pbar:
                for pwd in generate_passwords(min_length, max_length, characters):
                    future = executor.submit(check_hash, hash_fn, pwd, target_hash)
                    pbar.update(1)
                    if future.result():
                        return pwd
    else:
        print("[!] Either provide a wordlist or valid min/max length values.")
        return None

    return None

if __name__ == '__main__':
    print("=== Password Hash Cracker ===\n")

    target_hash = input("Enter the hash to crack: ").strip()

    print("\nDo you want to use a wordlist file or generate passwords?")
    print("1. Use a wordlist")
    print("2. Generate passwords")
    method = input("Enter 1 or 2: ").strip()

    wordlist_path = None
    min_len = 0
    max_len = 0

    if method == '1':
        wordlist_path = input("Enter the full path to the wordlist file: ").strip()
    elif method == '2':
        min_len = int(input("Enter minimum password length: "))
        max_len = int(input("Enter maximum password length: "))
    else:
        print("[!] Invalid selection.")
        exit()

    hash_type = input(f"Enter the hash type ({', '.join(hash_name)}): ").strip().lower()
    if not hash_type:
        hash_type = 'md5'

    max_workers = input("Enter number of threads (default 4): ").strip()
    max_workers = int(max_workers) if max_workers else 4

    characters = string.ascii_letters + string.digits  # You can customize this later if needed

    print("\n[*] Starting the crack...\n")

    result = crack_hash(target_hash, wordlist_path, hash_type, min_len, max_len, characters, max_workers)

    if result:
        print(f"\n[+] Password found: {result}")
    else:
        print("\n[!] Password not found.")
