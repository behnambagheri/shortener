"""Destination and short-name policy for the optional Django deployment."""
import json
import re
from urllib.parse import urlsplit, urlunsplit


def approved_domains(value):
    if isinstance(value, str):
        value = json.loads(value) if value.strip().startswith("[") else value.split(",")
    if not isinstance(value, list) or not value:
        raise ValueError("approved_domains must be a nonempty list.")
    result = set()
    for domain in value:
        if not isinstance(domain, str) or re.search(r"[\s/@:%*\\]", domain):
            raise ValueError("Invalid approved domain.")
        host = domain.rstrip(".").encode("idna").decode("ascii").lower()
        if len(host) > 253 or "." not in host or re.fullmatch(r"\d+(?:\.\d+){3}", host) or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            raise ValueError("Invalid approved domain.")
        result.add(host)
    return sorted(result)


def destination(value, domains, own_hosts=()):
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\x00-\x20\x7f\\]", value) or not re.match(r"https?://", value, re.I):
        raise ValueError("Enter a complete HTTP or HTTPS URL, up to 2,048 characters.")
    url = urlsplit(value)
    if url.scheme.lower() not in ("http", "https") or url.username or url.password or not url.hostname:
        raise ValueError("Use an HTTP or HTTPS URL without embedded credentials.")
    host = url.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    port = url.port
    if not any(host == domain or host.endswith("." + domain) for domain in domains):
        raise ValueError("That destination is not on an approved domain.")
    if host in own_hosts:
        raise ValueError("Use the original destination, rather than another short link.")
    authority = host + (f":{port}" if port and port != (443 if url.scheme.lower() == "https" else 80) else "")
    return urlunsplit((url.scheme.lower(), authority, url.path or "/", url.query, url.fragment))


def short_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", value) or value.lower() in {"api", "assets", "static", "health", "new"}:
        raise ValueError("Use 1–63 letters, numbers, hyphens, or underscores, and avoid reserved names.")
    return value
