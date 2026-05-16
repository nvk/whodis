import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

import requests

logger = logging.getLogger("whodis")

IANA_RDAP_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

_BOOTSTRAP_CACHE: Optional[Dict[str, Any]] = None


class RdapError(Exception):
    """Raised when an RDAP lookup cannot be completed."""


def fetch_dns_bootstrap(timeout: int = 10) -> Dict[str, Any]:
    global _BOOTSTRAP_CACHE

    if _BOOTSTRAP_CACHE is not None:
        return _BOOTSTRAP_CACHE

    response = requests.get(
        IANA_RDAP_DNS_BOOTSTRAP_URL,
        timeout=timeout,
        headers={"Accept": "application/json", "User-Agent": "whodis/0.2"},
    )
    response.raise_for_status()
    _BOOTSTRAP_CACHE = response.json()
    return _BOOTSTRAP_CACHE


def find_matching_rdap_services(domain: str, bootstrap: Dict[str, Any]) -> List[str]:
    labels = domain.lower().strip(".").split(".")
    best_match_len = -1
    best_urls: List[str] = []

    for entries, urls in bootstrap.get("services", []):
        for entry in entries:
            entry = entry.lower().strip(".")
            entry_labels = [] if entry == "" else entry.split(".")
            if entry and labels[-len(entry_labels):] != entry_labels:
                continue
            if not entry and best_match_len >= 0:
                continue

            match_len = len(entry_labels)
            if match_len > best_match_len:
                best_match_len = match_len
                best_urls = list(urls)
            elif match_len == best_match_len:
                best_urls.extend(urls)

    https_first = sorted(dict.fromkeys(best_urls), key=lambda url: not url.startswith("https://"))
    return https_first


def build_rdap_url(base_url: str, resource_type: str, value: str) -> str:
    base = base_url.rstrip("/") + "/"
    return urljoin(base, f"{resource_type}/{quote(value, safe='')}")


def lookup_domain_rdap(domain: str, timeout: int = 10) -> Dict[str, Any]:
    try:
        bootstrap = fetch_dns_bootstrap(timeout=timeout)
    except Exception as exc:
        return {
            "status": "error",
            "source": "rdap",
            "error": f"Could not fetch IANA RDAP bootstrap: {exc}",
        }

    urls = find_matching_rdap_services(domain, bootstrap)
    if not urls:
        return {
            "status": "no_service",
            "source": "rdap",
            "error": f"No RDAP service found in IANA bootstrap for {domain}",
            "bootstrap_publication": bootstrap.get("publication"),
        }

    errors = []
    for base_url in urls:
        query_url = build_rdap_url(base_url, "domain", domain)
        try:
            response = requests.get(
                query_url,
                timeout=timeout,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "whodis/0.2",
                },
            )
        except requests.RequestException as exc:
            errors.append({"url": query_url, "error": str(exc)})
            continue

        if response.status_code == 404:
            return {
                "status": "not_found",
                "source": "rdap",
                "query_url": query_url,
                "http_status": response.status_code,
                "bootstrap_publication": bootstrap.get("publication"),
            }

        if response.status_code == 429:
            errors.append({"url": query_url, "error": "rate_limited", "http_status": 429})
            continue

        if response.status_code >= 400:
            errors.append(
                {"url": query_url, "error": response.text[:300], "http_status": response.status_code}
            )
            continue

        try:
            raw = response.json()
        except ValueError as exc:
            errors.append({"url": query_url, "error": f"Non-JSON RDAP response: {exc}"})
            continue

        summary = summarize_rdap_domain(raw)
        summary.update(
            {
                "status": "ok",
                "source": "rdap",
                "query_url": query_url,
                "http_status": response.status_code,
                "bootstrap_publication": bootstrap.get("publication"),
                "raw": raw,
            }
        )
        return summary

    return {
        "status": "error",
        "source": "rdap",
        "error": "All RDAP services failed",
        "errors": errors,
        "bootstrap_publication": bootstrap.get("publication"),
    }


def summarize_rdap_domain(data: Dict[str, Any]) -> Dict[str, Any]:
    entities = data.get("entities", []) or []
    registrar = _find_entity_by_role(entities, "registrar")
    abuse = _find_entity_by_role(entities, "abuse")
    if registrar and not abuse:
        abuse = _find_entity_by_role(registrar.get("entities", []) or [], "abuse")

    event_map = _events_by_action(data.get("events", []) or [])
    nameservers = [
        ns.get("ldhName") or ns.get("unicodeName")
        for ns in data.get("nameservers", []) or []
        if ns.get("ldhName") or ns.get("unicodeName")
    ]

    return {
        "domain": data.get("ldhName") or data.get("unicodeName"),
        "unicode_domain": data.get("unicodeName"),
        "handle": data.get("handle"),
        "object_class": data.get("objectClassName"),
        "statuses": data.get("status", []) or [],
        "registrar": _entity_summary(registrar) if registrar else None,
        "abuse_contact": _entity_summary(abuse) if abuse else None,
        "events": event_map,
        "created": _first_event(event_map, "registration"),
        "expires": _first_event(event_map, "expiration"),
        "last_changed": _first_event(event_map, "last changed"),
        "rdap_updated": _first_event(event_map, "last update of RDAP database"),
        "nameservers": nameservers,
        "secure_dns": data.get("secureDNS"),
        "notices": _compact_notices(data.get("notices", []) or []),
        "remarks": _compact_notices(data.get("remarks", []) or []),
        "rdap_conformance": data.get("rdapConformance", []) or [],
        "redacted": bool(data.get("redacted")) or "redacted" in (data.get("rdapConformance", []) or []),
        "redaction": data.get("redacted"),
        "links": data.get("links", []) or [],
    }


def _find_entity_by_role(entities: List[Dict[str, Any]], role: str) -> Optional[Dict[str, Any]]:
    for entity in entities:
        if role in (entity.get("roles", []) or []):
            return entity
        nested = _find_entity_by_role(entity.get("entities", []) or [], role)
        if nested:
            return nested
    return None


def _entity_summary(entity: Dict[str, Any]) -> Dict[str, Any]:
    vcard = _parse_vcard(entity.get("vcardArray"))
    public_ids = entity.get("publicIds", []) or []
    iana_id = next(
        (item.get("identifier") for item in public_ids if item.get("type") == "IANA Registrar ID"),
        None,
    )
    return {
        "handle": entity.get("handle"),
        "roles": entity.get("roles", []) or [],
        "name": vcard.get("fn"),
        "email": vcard.get("email"),
        "phone": vcard.get("tel"),
        "iana_id": iana_id,
        "public_ids": public_ids,
    }


def _parse_vcard(vcard_array: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result

    for prop in vcard_array[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name = prop[0]
        value = prop[3]
        if name == "fn":
            result["fn"] = value
        elif name == "email":
            result["email"] = value
        elif name == "tel":
            result["tel"] = value
    return result


def _events_by_action(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    event_map: Dict[str, List[str]] = {}
    for event in events:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            event_map.setdefault(action, []).append(date)
    return event_map


def _first_event(events: Dict[str, List[str]], action: str) -> Optional[str]:
    values = events.get(action) or []
    return values[0] if values else None


def _compact_notices(notices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compact = []
    for notice in notices:
        compact.append(
            {
                "title": notice.get("title"),
                "description": notice.get("description", []) or [],
                "links": notice.get("links", []) or [],
            }
        )
    return compact


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
