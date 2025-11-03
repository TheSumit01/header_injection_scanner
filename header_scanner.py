import requests
import socket

# Step 1: Check if port is open
def is_port_open(host, port):
    try:
        socket.create_connection((host, port), timeout=3)
        return True
    except:
        return False

# Step 2: Send request, get headers, detect location
def check_for_location_header(domain, port):
    url = f"http://{domain}:{port}/"
    try:
        r = requests.get(url, timeout=5)
        if 'Location' in r.headers:
            print(f"[+] Location header found on {domain}:{port} -> {r.headers['Location']}")
            return r.headers['Location']
        else:
            print(f"[-] No Location header on {domain}:{port}")
    except Exception as e:
        print(f"[!] Error connecting to {domain}:{port}: {e}")
    return None

# Step 3: Test for header injection/poisoning
def test_header_poisoning(domain, port, original_location=None):
    url = f"http://{domain}:{port}/"
    headers = {
        'Host': 'evil.com',
        'X-Forwarded-Host': 'evil.com'
    }

    try:
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        location = r.headers.get('Location', '')

        if original_location and location != original_location:
            print(f"[!!!] Possible header poisoning on {domain}:{port}")
            print(f"      Original: {original_location}")
            print(f"      Injected: {location}")
            return True
        elif 'evil.com' in location:
            print(f"[!!!] Host injection reflected on {domain}:{port}")
            print(f"      Location: {location}")
            return True
        else:
            print(f"[~] No injection reflection detected on {domain}:{port}")
    except Exception as e:
        print(f"[!] Error during injection test: {e}")
    return False

# Orchestrator
def scan_domain(domain, ports=range(300, 400)):
    for port in ports:
        if not is_port_open(domain, port):
            print(f"[-] Port {port} not open on {domain}")
            continue

        print(f"[+] Scanning {domain}:{port}...")

        loc = check_for_location_header(domain, port)
        if loc:
            test_header_poisoning(domain, port, original_location=loc)

# Example usage
if __name__ == "__main__":
    targets = ["digitaldefynd.com", "gargicollege.in"]
    for domain in targets:
        scan_domain(domain)
