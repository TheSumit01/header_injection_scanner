import requests
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Proxy config (adjust if needed)
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
VERIFY_SSL = False  # Set to True if you have trusted certs

def check_and_test_header_poisoning(domain):
    url = f"http://{domain}/"
    result = {
        "domain": domain,
        "location_header": None,
        "header_poisoning": False,
        "header_injection": False,    # New field
        "original_location": None,
        "injected_location": None,
        "error": None
    }
    try:
        # Step 1: Send original request
        resp = requests.get(url, allow_redirects=False, timeout=5, proxies=PROXIES, verify=VERIFY_SSL)
        location = resp.headers.get('Location')
        result["location_header"] = bool(location)
        result["original_location"] = location

        if location:
            # Step 2: Send injected Host header request
            inj_headers = {"Host": "evil.com"}
            inj_resp = requests.get(url, headers=inj_headers, allow_redirects=False, timeout=5, proxies=PROXIES, verify=VERIFY_SSL)
            inj_location = inj_resp.headers.get('Location')
            result["injected_location"] = inj_location

            if inj_location and (("evil.com" in inj_location) or (inj_location != location)):
                result["header_poisoning"] = True
                result["header_injection"] = True
            else:
                # Request succeeded with injected header but no poisoning detected
                result["header_injection"] = True  
    except requests.RequestException as e:
        result["error"] = str(e)

    return result

def load_domains(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_results_csv(results, filename="results.csv"):
    keys = ["domain", "location_header", "header_poisoning", "header_injection", "original_location", "injected_location", "error"]
    with open(filename, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

def save_results_json(results, filename="results.json"):
    with open(filename, "w", encoding='utf-8') as jsonfile:
        json.dump(results, jsonfile, indent=2)

def main():
    domains = load_domains("domains.txt")
    print(f"Loaded {len(domains)} domains for scanning.\n")

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_and_test_header_poisoning, d): d for d in domains}
        for future in as_completed(futures):
            res = future.result()
            domain = futures[future]
            if res["error"]:
                print(f"[!] {domain} - Error: {res['error']}")
            else:
                status = "[VULNERABLE]" if res["header_poisoning"] else "[Safe]"
                print(f"{status} {domain} - Location Header: {res['location_header']} Header Injection: {res['header_injection']}")
            results.append(res)

    print("\nSaving results to 'results.csv' and 'results.json'...")
    save_results_csv(results)
    save_results_json(results)
    print("Done.")

if __name__ == "__main__":
    main()
