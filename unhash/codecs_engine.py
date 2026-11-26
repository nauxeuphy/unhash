import base64
import re
import urllib.parse
from collections import deque

def is_clean_printable(text: str) -> bool:
    if not text or len(text) < 2:
        return False
    printable_ratio = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\r\n\t') / len(text)
    return printable_ratio >= 0.95

def dec_hex(s: str) -> str:
    clean = s.strip()
    if len(clean) % 2 != 0 or not re.fullmatch(r'[0-9a-fA-F]+', clean):
        raise ValueError("Not valid hex")
    return bytes.fromhex(clean).decode('utf-8')

def dec_b64(s: str) -> str:
    clean = s.strip()
    if len(clean) < 4:
        raise ValueError("Too short for base64")
    padded = clean + "=" * ((4 - len(clean) % 4) % 4)
    if not re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}', padded):
        raise ValueError("Not valid base64")
    raw = base64.urlsafe_b64decode(padded) if ('-' in padded or '_' in padded) else base64.b64decode(padded)
    return raw.decode('utf-8')

def dec_b32(s: str) -> str:
    clean = s.strip()
    if len(clean) < 8 or len(clean) % 8 != 0 or not re.fullmatch(r'[A-Z2-7]+={0,6}', clean):
        raise ValueError("Not valid base32")
    return base64.b32decode(clean).decode('utf-8')

def dec_url(s: str) -> str:
    if '%' not in s and '+' not in s:
        raise ValueError("No URL encoding found")
    res = urllib.parse.unquote_plus(s)
    if res == s:
        raise ValueError("Unchanged")
    return res

def dec_bin(s: str) -> str:
    clean = s.replace(" ", "").strip()
    if len(clean) < 8 or len(clean) % 8 != 0 or not re.fullmatch(r'[01]+', clean):
        raise ValueError("Not valid binary")
    return "".join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))

def dec_rev(s: str) -> str:
    return s[::-1]

def dec_rot13(s: str) -> str:
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            out.append(c)
    return "".join(out)

CODECS = {
    "hex": ("Hex Decode", dec_hex),
    "b64": ("Base64 Decode", dec_b64),
    "b32": ("Base32 Decode", dec_b32),
    "url": ("URL Decode", dec_url),
    "bin": ("Binary Decode", dec_bin),
    "rev": ("Reverse String", dec_rev),
    "rot13": ("ROT13", dec_rot13),
}

def run_recipe(text: str, recipe_str: str):
    steps = [r.strip().lower() for r in recipe_str.split(",") if r.strip()]
    history = []
    current = text.strip()
    for step in steps:
        if step not in CODECS:
            raise ValueError(f"Unknown recipe '{step}'. Available: {', '.join(CODECS.keys())}")
        label, func = CODECS[step]
        current = func(current)
        history.append((label, current))
    return history

def auto_peel(text: str, max_depth: int = 5):
    queue = deque([(text.strip(), [])])
    visited = {text.strip()}
    candidates = []
    auto_ops = ["url", "hex", "b64", "b32", "bin", "rev"]

    while queue:
        current, path = queue.popleft()
        if len(path) >= max_depth:
            continue
        for op in auto_ops:
            if op == "rev" and path and path[-1][0] == "Reverse String":
                continue
            label, func = CODECS[op]
            try:
                out = func(current)
                if is_clean_printable(out) and out not in visited:
                    visited.add(out)
                    new_path = path + [(label, out)]
                    queue.append((out, new_path))
                    if op != "rev":
                        candidates.append(new_path)
            except Exception:
                continue
    return candidates
