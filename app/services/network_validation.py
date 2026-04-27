import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


def normalize_public_http_url(url: str, *, field_name: str = "url") -> str:
    candidate = url.strip()
    if not candidate:
        raise ValueError(f"{field_name} is required.")

    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        raise ValueError(f"{field_name} must be a valid http or https URL.")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not include embedded credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not include query parameters or fragments.")

    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError(f"{field_name} must not target localhost.")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValueError(f"{field_name} must not target private or non-global IP addresses.")

    normalized_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", "")).rstrip("/")


def validate_public_http_destination(url: str, *, field_name: str = "url") -> str:
    normalized = normalize_public_http_url(url, field_name=field_name)
    parsed = urlsplit(normalized)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        results = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {field_name} host: {parsed.hostname}") from exc

    for family, _, _, _, sockaddr in results:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise ValueError(f"{field_name} must resolve only to publicly routable addresses.")
    return normalized
