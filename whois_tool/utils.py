import datetime as dt
import hashlib
import logging
import re
import socket
import ssl
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import idna
import requests

logger = logging.getLogger("whodis")


def normalize_domain_input(value: str) -> Dict[str, Any]:
    original = value.strip()
    candidate = original

    if "://" not in candidate and "/" not in candidate and "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]

    if "://" not in candidate:
        candidate = "//" + candidate

    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    host = host.strip().strip(".").lower()

    try:
        ascii_domain = idna.encode(host, uts46=True).decode("ascii")
        unicode_domain = idna.decode(ascii_domain)
    except idna.IDNAError as exc:
        return {
            "original": original,
            "domain": host,
            "display_domain": host,
            "valid": False,
            "error": str(exc),
        }

    return {
        "original": original,
        "domain": ascii_domain,
        "display_domain": unicode_domain,
        "valid": is_valid_domain(ascii_domain),
        "idna": ascii_domain != unicode_domain,
    }


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    return all(label_pattern.match(label) for label in labels)


def is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except OSError:
            return False


def extract_from_text(text: str, pattern: str) -> Optional[str]:
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    if match and match.groups():
        return match.group(1).strip()
    return None


def extract_all_from_text(text: str, pattern: str) -> List[str]:
    matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
    return [match.strip() if isinstance(match, str) else match[0].strip() for match in matches]


def get_hosting_provider_map() -> Dict[str, List[str]]:
    return {
        "Amazon AWS": ["AMAZON", "AWS", "AMAZON-AES", "AS16509", "AS14618"],
        "Google Cloud": ["GOOGLE", "GOOGLECLOUD", "AS15169", "AS396982"],
        "Microsoft Azure": ["MICROSOFT", "MSFT", "AZURE", "AS8075"],
        "DigitalOcean": ["DIGITALOCEAN", "DIGITAL OCEAN", "AS14061"],
        "Cloudflare": ["CLOUDFLARE", "AS13335"],
        "OVH": ["OVH", "AS16276"],
        "Hetzner": ["HETZNER", "AS24940"],
        "Linode": ["LINODE", "AKAMAI", "AS63949"],
        "Vultr": ["VULTR", "AS20473"],
        "GoDaddy": ["GODADDY", "AS26496"],
        "Fastly": ["FASTLY", "AS54113"],
        "Akamai": ["AKAMAI", "AS20940"],
    }


def check_domain_redirect(domain: str, timeout: int = 5, max_redirects: int = 5) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "status": "not_checked",
        "redirects": False,
        "redirect_chain": [],
    }

    session = requests.Session()
    session.max_redirects = max_redirects
    headers = {"User-Agent": "whodis/0.2"}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True, headers=headers, stream=True)
            response.close()
        except requests.TooManyRedirects as exc:
            result.update({"status": "too_many_redirects", "initial_url": url, "error": str(exc)})
            return result
        except requests.RequestException as exc:
            result.update({"status": "error", "initial_url": url, "error": str(exc)})
            continue

        history = [item.url for item in response.history]
        result.update(
            {
                "status": "ok",
                "initial_url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "redirects": bool(history),
                "redirect_chain": history,
                "domain_changed": urlparse(url).netloc != urlparse(response.url).netloc,
            }
        )
        return result

    return result


def get_ssl_certificate_info(domain: str, timeout: int = 5, port: int = 443) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "port": port,
        "status": "not_checked",
        "has_tls": False,
        "verified": False,
    }

    try:
        cert, connection = _fetch_certificate(domain, port, timeout, verify=True)
        result["verified"] = True
        result["status"] = "ok"
    except ssl.SSLCertVerificationError as exc:
        result["verification_error"] = str(exc)
        try:
            cert, connection = _fetch_certificate(domain, port, timeout, verify=False)
            result["status"] = "verification_failed"
        except Exception as inner_exc:
            result.update({"status": "tls_error", "error": str(inner_exc)})
            return result
    except Exception as exc:
        result.update({"status": "connection_error", "error": str(exc)})
        return result

    result["has_tls"] = True
    result.update(connection)
    result.update(_format_certificate(cert))
    return result


def _fetch_certificate(domain: str, port: int, timeout: int, verify: bool) -> tuple[Dict[str, Any], Dict[str, Any]]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert() if verify else _decode_der_certificate(der_cert)
            connection = {
                "tls_version": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                "fingerprint_sha256": hashlib.sha256(der_cert).hexdigest() if der_cert else None,
            }
            return cert, connection


def _decode_der_certificate(der_cert: bytes) -> Dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der_cert)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as handle:
        handle.write(pem)
        handle.flush()
        return ssl._ssl._test_decode_cert(handle.name)  # type: ignore[attr-defined]


def _format_certificate(cert: Dict[str, Any]) -> Dict[str, Any]:
    subject = _name_tuples_to_dict(cert.get("subject", []))
    issuer = _name_tuples_to_dict(cert.get("issuer", []))
    not_after = cert.get("notAfter")

    formatted: Dict[str, Any] = {
        "subject": subject,
        "issuer": issuer,
        "common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "issuer_organization": issuer.get("organizationName"),
        "valid_from": cert.get("notBefore"),
        "valid_until": not_after,
        "serial_number": cert.get("serialNumber"),
        "subject_alt_names": [
            value for value_type, value in cert.get("subjectAltName", []) if value_type == "DNS"
        ],
    }

    if not_after:
        try:
            expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            formatted["days_remaining"] = (expiry - dt.datetime.now(dt.timezone.utc)).days
        except ValueError:
            pass

    return formatted


def _name_tuples_to_dict(items: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for group in items:
        for key, value in group:
            result[key] = value
    return result
