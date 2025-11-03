import asyncio
import aiohttp

HEADERS_TO_TEST = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-For",
    "Forwarded"
]

MAX_REDIRECTS = 5
INJECTION_PAYLOAD = "evil.com"

class ScanResult:
    def __init__(self, domain):
        self.domain = domain
        self.location_header_found = False
        self.header_poisoning = False
        self.header_injection = False
        self.original_redirect_chain = []
        self.injection_results = {}  # header_name: redirect_chain or None
        self.errors = []

    def to_dict(self):
        return {
            "domain": self.domain,
            "location_header_found": self.location_header_found,
            "header_poisoning": self.header_poisoning,
            "header_injection": self.header_injection,
            "original_redirect_chain": self.original_redirect_chain,
            "injection_results": self.injection_results,
            "errors": self.errors
        }

async def fetch_redirect_chain(session, url, headers=None):
    chain = []
    try:
        for _ in range(MAX_REDIRECTS):
            async with session.get(url, headers=headers, allow_redirects=False) as resp:
                location = resp.headers.get("Location")
                chain.append({
                    "url": url,
                    "status": resp.status,
                    "location": location
                })
                if not location:
                    break
                if location.startswith("/"):
                    # Relative redirect: join with base url
                    from urllib.parse import urljoin
                    url = urljoin(url, location)
                else:
                    url = location
        return chain
    except Exception as e:
        raise e

async def scan_domain(session, domain):
    result = ScanResult(domain)
    base_url = f"http://{domain}/"

    try:
        # 1) Get original redirect chain
        original_chain = await fetch_redirect_chain(session, base_url)
        result.original_redirect_chain = original_chain
        result.location_header_found = any(step["location"] for step in original_chain)

        if not result.location_header_found:
            # No redirects found, no poisoning possible, mark injection False
            return result.to_dict()

        # 2) For each header to test, inject payload and get redirect chain
        for header in HEADERS_TO_TEST:
            inj_headers = {header: INJECTION_PAYLOAD}
            try:
                inj_chain = await fetch_redirect_chain(session, base_url, headers=inj_headers)
                result.injection_results[header] = inj_chain

                # Analyze if injection caused poisoning:
                # Check if any Location header contains the payload or differs from original
                poisoning_found = False
                for orig_step, inj_step in zip(original_chain, inj_chain):
                    orig_loc = orig_step.get("location")
                    inj_loc = inj_step.get("location")
                    if inj_loc and (INJECTION_PAYLOAD in inj_loc or inj_loc != orig_loc):
                        poisoning_found = True
                        break

                if poisoning_found:
                    result.header_poisoning = True
                    result.header_injection = True
                    # No need to check further if one header is vulnerable, but we continue for full report
            except Exception as e:
                result.errors.append(f"Header {header} error: {str(e)}")

        # If no poisoning found but injected requests succeeded, mark header_injection True
        if not result.header_injection and len(result.injection_results) > 0:
            result.header_injection = True

    except Exception as e:
        result.errors.append(str(e))

    return result.to_dict()

async def scan_domains(domains, concurrency=10):
    results = []
    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        semaphore = asyncio.Semaphore(concurrency)

        async def sem_task(domain):
            async with semaphore:
                return await scan_domain(session, domain)

        tasks = [sem_task(d) for d in domains]
        for f in asyncio.as_completed(tasks):
            res = await f
            results.append(res)
    return results 