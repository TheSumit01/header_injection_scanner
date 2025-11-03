import requests

# Configure your proxy here (Burp usually runs on localhost:8080)
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# Set to True if your Burp proxy uses a self-signed cert and you want to ignore SSL warnings
VERIFY_SSL = False

def check_and_test_header_poisoning(domain):
    url = f"http://{domain}/"
    try:
        # Step 1: Send original request without injection
        resp = requests.get(url, allow_redirects=False, timeout=5, proxies=PROXIES, verify=VERIFY_SSL)
        location = resp.headers.get('Location')

        if location:
            print(f"[+] {domain} has Location header: {location}")
            # Step 2: Try header poisoning by injecting Host header
            injected_headers = {
                "Host": "evil.com"
            }
            inj_resp = requests.get(url, headers=injected_headers, allow_redirects=False, timeout=5, proxies=PROXIES, verify=VERIFY_SSL)
            inj_location = inj_resp.headers.get('Location')

            if inj_location and ("evil.com" in inj_location or inj_location != location):
                print(f"[!!!] Possible header poisoning on {domain}")
                print(f"     Original Location: {location}")
                print(f"     Injected Location: {inj_location}\n")
            else:
                print(f"[~] No header poisoning detected on {domain}\n")
        else:
            print(f"[-] No Location header found on {domain}\n")

    except requests.RequestException as e:
        print(f"[!] Error connecting to {domain}: {e}\n")

if __name__ == "__main__":
    # Example domains to test
    domains = [
        "example.com",
        "digitaldefynd.com",
        "gargicollege.in"
    ]

    for d in domains:
        check_and_test_header_poisoning(d)
