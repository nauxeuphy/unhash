import base64
import hashlib
import os
import re
import urllib.parse

HASH_PATTERNS = [
    (r'^[a-fA-F0-9]{32}$', "MD5 / NTLM", "md5"),
    (r'^[a-fA-F0-9]{40}$', "SHA-1", "sha1"),
    (r'^[a-fA-F0-9]{56}$', "SHA-224", "sha224"),
    (r'^[a-fA-F0-9]{64}$', "SHA-256", "sha256"),
    (r'^[a-fA-F0-9]{96}$', "SHA-384", "sha384"),
    (r'^[a-fA-F0-9]{128}$', "SHA-512", "sha512"),
    (r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$', "Bcrypt", None),
]

KNOWN_MAGIC_INPUTS = {
    "240610708": ("MD5", "0e462097431906509019562988736854"),
    "QNKCDZO": ("MD5", "0e830400451993494058024219903391"),
    "aabg7XSs": ("MD5", "0e087386482136013740957780965295"),
    "314282422": ("MD5", "0e990995504821699494520356953734"),
    "10932435112": ("SHA-1", "0e07766915004133176347055865026311692244"),
}

BUILTIN_COMMON_WORDS = [
    "admin", "password", "123456", "12345678", "12345", "123456789", "qwerty",
    "abc123", "password1", "admin123", "root", "toor", "guest", "test", "secret",
    "rahasia", "rahasia123", "indonesia", "letmein", "welcome", "monkey", "dragon",
    "master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "123123",
    "pass", "pass123", "password123", "naufal", "flag", "ctf", "natas", "pwned",
    "iloveyou", "sunshine", "princess", "football", "shadow", "superman", "batman"
]

def is_php_magic_hash(s: str) -> bool:
    clean = s.strip()
    return bool(re.match(r'^0+[eE]\d+$', clean))

def identify_hash(s: str):
    clean = s.strip()
    return [(name, algo) for pattern, name, algo in HASH_PATTERNS if re.match(pattern, clean)]

def generate_all_hashes_and_encodings(text: str) -> dict:
    raw_bytes = text.encode("utf-8")
    return {
        "MD5": hashlib.md5(raw_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(raw_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(raw_bytes).hexdigest(),
        "SHA-512": hashlib.sha512(raw_bytes).hexdigest(),
        "Base64": base64.b64encode(raw_bytes).decode("utf-8"),
        "Hex": raw_bytes.hex(),
        "URL-Encoded": urllib.parse.quote(text, safe=""),
    }

def crack_hash_wordlist(target_hash: str, algo: str, wordlist_path: str = None):
    target = target_hash.strip().lower()
    if not algo:
        return None

    # 1. Check magic inputs first
    for pt, (_, h) in KNOWN_MAGIC_INPUTS.items():
        if h.lower() == target:
            return pt

    # 2. Check built-in common CTF words
    for word in BUILTIN_COMMON_WORDS:
        if hashlib.new(algo, word.encode("utf-8")).hexdigest().lower() == target:
            return word

    # 3. Check user-specified wordlist or auto-discover local wordlists
    candidate_paths = []
    if wordlist_path:
        candidate_paths.append(wordlist_path)
    for default_wl in [
        "/home/nopalxasanagi/wordlists/common.txt",
        "/mnt/c/Users/naufa/wordlists/common.txt",
        "/usr/share/wordlists/rockyou.txt",
    ]:
        if os.path.isfile(default_wl) and default_wl not in candidate_paths:
            candidate_paths.append(default_wl)

    for path in candidate_paths:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if hashlib.new(algo, word.encode("utf-8")).hexdigest().lower() == target:
                    return word
    return None
