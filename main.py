import argparse
import sys
import json
from extractor import IOCExtractor

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

BANNER = f"""{CYAN}
  ___ ___  ___   _____  _______ ___    _   ___ _____ ___  ___ 
 |_ _| __|/ _ \ / _ \ \/ /_   _| _ \  /_\ / __|_   _/ _ \| _ \\
  | || _|| (_) | (_) >  <  | | |   / / _ \ (__  | || (_) |   /
 |___|___|\___/ \___/_/\_\ |_| |_|_\/_/ \_\___| |_| \___/|_|_\\
{RESET}   Automated Indicators of Compromise Extractor v1.0
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="IOC Extractor & Defanger")
    parser.add_argument("file", help="Path to raw security text file/log")
    parser.add_argument("--no-defang", action="store_true", help="Do not defang IPs/URLs (Keep live links)")
    parser.add_argument("-o", "--output", help="Save extracted IOCs to JSON file")
    args = parser.parse_args()

    try:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()

        extractor = IOCExtractor(text)
        iocs = extractor.extract(defang=not args.no_defang)

        print(f"[*] Analyzing file: {YELLOW}{args.file}{RESET}...")
        print("-" * 50)

        total_count = 0
        for ioc_type, items in iocs.items():
            if items:
                total_count += len(items)
                print(f"{CYAN}[+] {ioc_type.upper()} ({len(items)}){RESET}")
                for item in items:
                    print(f"   • {item}")
                print()

        print("-" * 50)
        print(f"[*] Extraction complete! Found {GREEN}{total_count}{RESET} unique IOCs.")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(iocs, f, indent=4)
            print(f"[+] Exported JSON report to {CYAN}{args.output}{RESET}")

    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
