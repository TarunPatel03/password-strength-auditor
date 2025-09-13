import hashlib
import requests
from typing import Optional

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

def hibp_breach_count(password: str, timeout: float = 6.0) -> Optional[int]:
    """Return breach count from HIBP range API, or None if network error."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(HIBP_RANGE_URL.format(prefix), timeout=timeout)
        if r.status_code != 200:
            return None
        for line in r.text.splitlines():
            h, cnt = line.split(":")
            if h == suffix:
                return int(cnt)
        return 0
    except requests.RequestException:
        return None
