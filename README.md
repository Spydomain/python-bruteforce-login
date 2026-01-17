# Bulk Login Tester

A lightweight, automated Python script designed to audit HTTP authentication endpoints using credential lists. This tool is intended for security researchers and system administrators to test the strength of web application login forms against credential stuffing attacks.

## ⚠️ Legal Disclaimer

**Please read before use:**

This tool is developed for **educational purposes and authorized security testing only**.
* Do not use this tool on targets you do not have explicit permission to audit.
* The developer is not responsible for any misuse, damage, or illegal activity caused by this tool.
* By using this software, you agree to comply with all applicable local and international laws regarding cybersecurity.

---

## Features

* **Combo List Support:** simple parsing of `username:password` text files.
* **Session Management:** Uses `requests.Session` for efficient connection pooling.
* **JSON Payload:** automatically formats requests as `application/json`.
* **Smart Error Handling:** Includes retry logic for connection timeouts and errors.
* **Custom Headers:** mimics legitimate browser traffic with custom User-Agent headers.
* **Real-time Feedback:** displays success/failure status per attempt.

## Prerequisites

* Python 3.6+
* `requests` library

## Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/Spydomain/python-bruteforce-login.git](https://github.com/Spydomain/python-bruteforce-login.git)
    cd python-bruteforce-login
    ```

2.  **Install dependencies**
    ```bash
    pip install requests
    ```

## Usage

1.  **Prepare your credentials file**
    Create a text file (e.g., `wordlist.txt`) containing credentials in `username:password` format, with one pair per line:
    ```text
    admin:123456
    user:password
    test:test
    ```

2.  **Run the script**
    ```bash
    python3 bulk-login-tester.py wordlist.txt
    ```

3.  **Enter the target URL**
    When prompted, paste the full URL of the login API endpoint (e.g., `http://target-site.com/api/login`).

### Example Output

```text
[*] Loaded 50 credential pairs
[*] Target: http://localhost:8080/api/login

[-] Failed: admin
[-] Failed: user
[+] SUCCESS!
[+] Username: admin
[+] Password: secretpass
[+] Response: {"token": "eyJhGciOi..."}
