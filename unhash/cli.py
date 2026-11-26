#!/usr/bin/env python3
import argparse
import json
import sys
from unhash.codecs_engine import run_recipe, auto_peel, CODECS
from unhash.ciphers import brute_caesar, brute_xor_hex
from unhash.hashes import identify_hash, crack_hash_wordlist
from unhash.web_pentest import is_jwt, inspect_jwt, inspect_cookie, known_plaintext_xor

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  unhash v1.0 — Zero-Dep CLI CyberChef & Web Pentest Inspector    ║")
    print(f"╚══════════════════════════════════════════════════════════════════╝{RESET}")

def main():
    parser = argparse.ArgumentParser(
        prog="unhash",
        description="Zero-dependency CLI multi-decoder, JWT/Cookie inspector, XOR forger, and hash analyzer."
    )
    parser.add_argument("-help", action="help", help="Show this help message and exit")
    parser.add_argument("input", nargs="?", help="Input string, cookie, or JWT (or pipe via stdin)")
    parser.add_argument("-a", "--auto", action="store_true", help="Magic Auto-Peel multi-layer encodings (BFS)")
    parser.add_argument("-r", "--recipe", help=f"Deterministic recipe (e.g. hex,rev,b64). Ops: {','.join(CODECS.keys())}")
    parser.add_argument("--jwt", action="store_true", help="Force JWT token inspection & security audit")
    parser.add_argument("--cookie", action="store_true", help="Inspect Web Cookie (URL + Base64 + JSON/PHP/XOR)")
    parser.add_argument("--kpt", help="Known-Plaintext string to recover repeating XOR key from Base64/Hex cookie")
    parser.add_argument("--forge", help="New plaintext to forge using the recovered XOR key (used with --kpt)")
    parser.add_argument("--caesar", action="store_true", help="Brute-force all 25 Caesar/ROT shifts")
    parser.add_argument("--xor-hex", action="store_true", help="Brute-force single-byte XOR against hex input")
    parser.add_argument("-w", "--wordlist", help="Wordlist path for hash dictionary cracking")
    parser.add_argument("-g", "--grep", help="Filter output containing specific substring (e.g. 'flag{')")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide banner")

    args = parser.parse_args()
    raw_input = args.input
    if not raw_input and not sys.stdin.isatty():
        raw_input = sys.stdin.read().strip()

    if not raw_input:
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        print_banner()
    print(f"{BOLD}[Input]{RESET} {raw_input}\n")

    if args.kpt:
        print(f"{YELLOW}{BOLD}[*] Running Known-Plaintext XOR Key Recovery...{RESET}")
        res = known_plaintext_xor(raw_input, args.kpt, args.forge)
        print(f"  ├─► {CYAN}Full Keystream :{RESET} {res['keystream_str']}")
        print(f"  ├─► {GREEN}{BOLD}Repeating Key  :{RESET} {BOLD}{res['repeating_key_str']}{RESET} (hex: {res['repeating_key_hex']})")
        if res["forged_b64"]:
            print(f"  └─► {GREEN}{BOLD}Forged Cookie  :{RESET} {BOLD}{res['forged_b64']}{RESET}")
        return

    if args.jwt or is_jwt(raw_input):
        print(f"{YELLOW}{BOLD}[*] JWT Token Detected — Running Security Audit:{RESET}")
        info = inspect_jwt(raw_input)
        print(f"  ├─► {CYAN}Header    :{RESET} {json.dumps(info['header'])}")
        print(f"  ├─► {CYAN}Payload   :{RESET} {json.dumps(info['payload'])}")
        print(f"  ├─► {CYAN}Signature :{RESET} {info['signature']}")
        for w in info["warnings"]:
            col = RED if "CRITICAL" in w else YELLOW
            print(f"  └─► {col}{BOLD}[Audit]{RESET} {w}")
        return

    if args.cookie:
        print(f"{YELLOW}{BOLD}[*] Inspecting Web Cookie:{RESET}")
        c_info = inspect_cookie(raw_input)
        print(f"  ├─► {CYAN}Cookie Name :{RESET} {c_info['name']}")
        for s_lbl, s_val in c_info["steps"]:
            print(f"  ├─► {CYAN}{s_lbl:22s}:{RESET} {s_val}")
        print(f"  └─► {GREEN}{BOLD}Detected Format :{RESET} {c_info['format']}")
        return

    if args.recipe:
        steps = run_recipe(raw_input, args.recipe)
        for idx, (label, val) in enumerate(steps, 1):
            prefix = "└─►" if idx == len(steps) else "├─►"
            color = GREEN + BOLD if idx == len(steps) else CYAN
            print(f"  {prefix} {color}[Step {idx}: {label}]{RESET} {val}")
        return

    if args.caesar:
        print(f"{YELLOW}{BOLD}[*] Caesar / ROT Brute-Force:{RESET}")
        for label, out in brute_caesar(raw_input, args.grep):
            print(f"  {CYAN}{label}{RESET} : {out}")
        return

    if args.xor_hex:
        print(f"{YELLOW}{BOLD}[*] Single-Byte XOR Brute-Force:{RESET}")
        for label, out in brute_xor_hex(raw_input, args.grep):
            print(f"  {CYAN}{label}{RESET} : {out}")
        return

    hash_types = identify_hash(raw_input)
    if hash_types:
        names = ", ".join(h[0] for h in hash_types)
        print(f"{YELLOW}[i] Possible Hash Format:{RESET} {BOLD}{names}{RESET}")
        if args.wordlist and hash_types[0][1]:
            found = crack_hash_wordlist(raw_input, hash_types[0][1], args.wordlist)
            if found:
                print(f"  └─► {GREEN}{BOLD}[Cracked!]{RESET} {found}\n")

    print(f"{CYAN}{BOLD}[*] Running Magic Auto-Peel (Multi-Layer BFS)...{RESET}")
    candidates = auto_peel(raw_input)
    if not candidates:
        print(f"  └─► {RED}No automatic decoding chain found. Try --cookie, --caesar, or --kpt.{RESET}")
    else:
        for c_idx, path in enumerate(candidates, 1):
            final_val = path[-1][1]
            if args.grep and args.grep.lower() not in final_val.lower():
                continue
            print(f"\n  {BOLD}Chain #{c_idx}:{RESET}")
            for s_idx, (label, val) in enumerate(path, 1):
                is_last = s_idx == len(path)
                branch = "└─►" if is_last else "├─►"
                col = GREEN + BOLD if is_last else CYAN
                print(f"    {branch} {col}[Layer {s_idx}: {label}]{RESET} {val}")

if __name__ == "__main__":
    main()
