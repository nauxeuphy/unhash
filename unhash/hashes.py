import hashlib
import re

HASH_PATTERNS = [
    (r'^[a-fA-F0-9]{32}$', "MD5 / NTLM", "md5"),
    (r'^[a-fA-F0-9]{40}$', "SHA-1", "sha1"),
    (r'^[a-fA-F0-9]{56}$', "SHA-224", "sha224"),
    (r'^[a-fA-F0-9]{64}$', "SHA-256", "sha256"),
    (r'^[a-fA-F0-9]{96}$', "SHA-384", "sha384"),
    (r'^[a-fA-F0-9]{128}$', "SHA-512", "sha512"),
    (r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$', "Bcrypt", None),
]

def identify_hash(s: str):
    clean = s.strip()
    return [(name, algo) for pattern, name, algo in HASH_PATTERNS if re.match(pattern, clean)]

def crack_hash_wordlist(target_hash: str, algo: str, wordlist_path: str):
    target = target_hash.strip().lower()
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if hashlib.new(algo, word.encode("utf-8")).hexdigest().lower() == target:
                return word
    return None
