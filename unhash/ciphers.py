def brute_caesar(text: str, grep_filter: str = None):
    results = []
    for shift in range(1, 26):
        shifted = []
        for c in text:
            if 'a' <= c <= 'z':
                shifted.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                shifted.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                shifted.append(c)
        out = "".join(shifted)
        if not grep_filter or grep_filter.lower() in out.lower():
            results.append((f"ROT+{shift:02d}", out))
    return results

def brute_xor_hex(hex_str: str, grep_filter: str = None):
    raw = bytes.fromhex(hex_str.strip())
    results = []
    for key in range(1, 256):
        decoded_bytes = bytes(b ^ key for b in raw)
        try:
            text = decoded_bytes.decode('utf-8')
            if all(32 <= ord(c) <= 126 for c in text):
                if not grep_filter or grep_filter.lower() in text.lower():
                    results.append((f"Key 0x{key:02x} ('{chr(key)}')", text))
        except Exception:
            continue
    return results
