"""
IOC Classifier — determines the type of an Indicator of Compromise.
"""

import re

# Regex patterns
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _strip_port(ioc: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", ioc):
        return ioc.split(":")[0]
    return ioc


def classify_ioc(ioc: str) -> str:
    """
    Classify an IOC string as: 'ip', 'domain', 'hash', or 'unknown'.
    Strips URLs to extract just the domain if needed.
    Handles IP:port formats (e.g. '1.2.3.4:8080') by stripping the port.
    """
    ioc = ioc.strip()

    if URL_RE.match(ioc):
        from urllib.parse import urlparse
        parsed = urlparse(ioc)
        ioc = parsed.netloc or ioc

    ioc_no_port = _strip_port(ioc)
    if IPV4_RE.match(ioc_no_port):
        host = ioc_no_port.split(":")[0] if ":" in ioc_no_port else ioc_no_port
        parts = host.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"

    if MD5_RE.match(ioc) or SHA1_RE.match(ioc) or SHA256_RE.match(ioc):
        return "hash"

    if DOMAIN_RE.match(ioc):
        return "domain"

    return "unknown"


def extract_ioc_from_text(text: str) -> str | None:
    """
    Scan free text for the first IOC pattern found.
    Strips URL scheme to extract domain when needed.
    Returns the raw IOC string or None.
    """
    text = text.strip()
    if not text:
        return None

    stripped_url = text
    if URL_RE.match(text):
        from urllib.parse import urlparse
        parsed = urlparse(text)
        stripped_url = parsed.netloc or text

    for pattern in (IPV4_RE, MD5_RE, SHA1_RE, SHA256_RE, DOMAIN_RE):
        m = pattern.search(stripped_url)
        if m:
            return m.group(0)
    return None


def validate_ioc(ioc: str) -> tuple[bool, str]:
    """
    Returns (is_valid, message).
    """
    ioc_type = classify_ioc(ioc)
    if ioc_type == "unknown":
        return False, f"Could not classify '{ioc}' as a valid IP, domain, or hash."
    return True, f"Valid {ioc_type}: {ioc}"


if __name__ == "__main__":
    # Quick tests
    test_cases = [
        "8.8.8.8",
        "192.168.56.3",
        "malware.example.com",
        "https://phishing-site.ru/login",
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        "not_an_ioc",
    ]
    for t in test_cases:
        print(f"{t!r:55} → {classify_ioc(t)}")
