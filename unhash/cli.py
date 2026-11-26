#!/usr/bin/env python3
import argparse
import json
import sys
from unhash.codecs_engine import run_recipe, auto_peel, CODECS
from unhash.ciphers import brute_caesar, brute_xor_hex
from unhash.hashes import identify_hash, crack_hash_wordlist, is_php_magic_hash, KNOWN_MAGIC_INPUTS
from unhash.web_pentest import is_jwt, inspect_jwt, inspect_cookie, known_plaintext_xor

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  unhash v1.1 — Zero-Dep CLI CyberChef & Web Pentest Inspector    ║")
    print(f"╚══════════════════════════════════════════════════════════════════╝{RESET}")

def print_php_juggling_guide():
    print(f"{YELLOW}{BOLD}[*] PHP Type Juggling, Magic Hash (0e) & Auth Bypass Payloads:{RESET}\n")
    print(f"  {CYAN}{BOLD}1. MD5 Magic Hashes (untuk `md5($input) == '0e...'` atau `md5($a) == md5($b)`):{RESET}")
    print(f"     ├─► Input Angka    : {GREEN}{BOLD}240610708{RESET}   -> MD5: 0e462097431906509019562988736854 (== 0)")
    print(f"     ├─► Input Huruf    : {GREEN}{BOLD}QNKCDZO{RESET}     -> MD5: 0e830400451993494058024219903391 (== 0)")
    print(f"     ├─► Input Campuran : {GREEN}{BOLD}aabg7XSs{RESET}    -> MD5: 0e087386482136013740957780965295 (== 0)")
    print(f"     └─► Dual Collision : {GREEN}{BOLD}?user1=240610708&user2=QNKCDZO{RESET}\n")
    print(f"  {CYAN}{BOLD}2. SHA-1 Magic Hash (untuk `sha1($input) == '0e...'`):{RESET}")
    print(f"     └─► Input Angka    : {GREEN}{BOLD}10932435112{RESET} -> SHA1: 0e07766915004133176347055865026311692244 (== 0)\n")
    print(f"  {CYAN}{BOLD}3. Array Injection Bypass (`strcmp` & Strict `md5($a) === md5($b)`):{RESET}")
    print(f"     ├─► Bypass strcmp()       : {GREEN}{BOLD}pass[]=a{RESET}         (strcmp(Array, str) -> NULL == 0 -> TRUE)")
    print(f"     └─► Bypass md5() === md5(): {GREEN}{BOLD}?user1[]=1&user2[]=2{RESET} (md5(Array) -> NULL === NULL -> TRUE)\n")
    print(f"  {CYAN}{BOLD}4. JSON Loose Comparison Bypass (`$data['password'] == $secret`):{RESET}")
    print(f"     └─► Payload JSON          : {GREEN}{BOLD}{{\"username\": \"admin\", \"password\": true}}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        prog="unhash",
        description="Zero-dependency CLI multi-decoder, JWT/Cookie inspector, XOR forger, PHP Magic Hash & hash analyzer."
    )
    parser.add_argument("-help", action="help", help="Show this help message and exit")
    parser.add_argument("input", nargs="?", help="Input string, cookie, JWT, hash, or 'php'")
    parser.add_argument("-a", "--auto", action="store_true", help="Magic Auto-Peel multi-layer encodings (BFS)")
    parser.add_argument("-r", "--recipe", help=f"Deterministic recipe (e.g. hex,rev,b64). Ops: {','.join(CODECS.keys())}")
    parser.add_argument("--jwt", action="store_true", help="Force JWT token inspection & security audit")
    parser.add_argument("--cookie", action="store_true", help="Inspect Web Cookie (URL + Base64 + JSON/PHP/XOR)")
    parser.add_argument("--php", action="store_true", help="Show PHP Type Juggling & Magic Hash (0e) bypass payloads")
    parser.add_argument("--kpt", help="Known-Plaintext string to recover repeating XOR key from Base64/Hex cookie")
    parser.add_argument("--forge", help="New plaintext to forge using the recovered XOR key (used with --kpt)")
    parser.add_argument("--caesar", action="store_true", help="Brute-force all 25 Caesar/ROT shifts")
    parser.add_argument("--xor-hex", action="store_true", help="Brute-force single-byte XOR against hex input")
    parser.add_argument("-w", "--wordlist", help="Wordlist path for hash dictionary cracking")
    parser.add_argument("-g", "--grep", help="Filter output containing specific substring (e.g. 'flag{')")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide banner")

    args = parser.parse_args()
    raw_input = args.input

    if args.php or (raw_input and raw_input.strip().lower() == "php"):
        if not args.quiet:
            print_banner()
        print_php_juggling_guide()
        return

    if not raw_input and not sys.stdin.isatty():
        raw_input = sys.stdin.read().strip()

    if not raw_input:
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        print_banner()
    print(f"{BOLD}[Input]{RESET} {raw_input}\n")

    if raw_input.strip() in KNOWN_MAGIC_INPUTS:
        algo_name, h_val = KNOWN_MAGIC_INPUTS[raw_input.strip()]
        print(f"{GREEN}{BOLD}[!] Known PHP Magic Hash Payload Detected!{RESET}")
        print(f"  ├─► {CYAN}Algorithm  :{RESET} {algo_name}")
        print(f"  ├─► {CYAN}Output Hash:{RESET} {GREEN}{BOLD}{h_val}{RESET}")
        print(f"  └─► {YELLOW}PHP (==) evaluates this hash as scientific notation 0 * 10^... == 0 (TRUE)!{RESET}\n")

    if is_php_magic_hash(raw_input):
        exact_pt = next((pt for pt, (alg, h) in KNOWN_MAGIC_INPUTS.items() if h.lower() == raw_input.strip().lower()), None)
        print(f"{RED}{BOLD}[!] CRITICAL: PHP Magic Hash / Type Juggling Pattern Detected (`0e` + all digits)!{RESET}")
        if exact_pt:
            print(f"  ├─► {GREEN}{BOLD}[Exact Plaintext Match]   :{RESET} {GREEN}{BOLD}{exact_pt}{RESET} (Teks asli dari hash ini!)")
        print(f"  ├─► {YELLOW}In PHP (`==`), '{raw_input.strip()}' == 0, so ANY of these magic inputs can bypass it:{RESET}")
        print(f"  ├─► {CYAN}MD5 Magic Digits #1       :{RESET} {BOLD}240610708{RESET}   (md5 -> 0e462097431906509019562988736854)")
        print(f"  ├─► {CYAN}MD5 Magic Digits #2       :{RESET} {BOLD}314282422{RESET}   (md5 -> 0e990995504821699494520356953734)")
        print(f"  ├─► {CYAN}MD5 Magic Letters         :{RESET} {BOLD}QNKCDZO{RESET}     (md5 -> 0e830400451993494058024219903391)")
        print(f"  ├─► {CYAN}MD5 Magic Mixed           :{RESET} {BOLD}aabg7XSs{RESET}    (md5 -> 0e087386482136013740957780965295)")
        print(f"  └─► {CYAN}SHA-1 Magic Digits        :{RESET} {BOLD}10932435112{RESET} (sha1 -> 0e07766915004133176347055865026311692244)\n")

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
        print(f"  └─► {RED}No automatic decoding chain found. Try --cookie, --caesar, --php, or --kpt.{RESET}")
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
