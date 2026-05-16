import logging
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

from whois_tool.utils import is_valid_domain

logger = logging.getLogger("whodis")

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "DS", "DNSKEY"]


def resolve_dns_python(domain: str, record_type: str, timeout: int = 10) -> Dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(max(timeout / 2, 1), timeout)
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, record_type, lifetime=timeout, raise_on_no_answer=True)
        records = [format_dns_answer(answer, record_type) for answer in answers]
        return {"status": "ok", "records": records}
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "no_answer", "records": []}
    except dns.resolver.NoNameservers as exc:
        return {"status": "no_nameservers", "records": [], "error": str(exc)}
    except dns.exception.Timeout as exc:
        return {"status": "timeout", "records": [], "error": str(exc)}
    except Exception as exc:
        logger.debug("Error resolving %s %s: %s", domain, record_type, exc)
        return {"status": "error", "records": [], "error": str(exc)}


def format_dns_answer(answer: Any, record_type: str) -> Any:
    if record_type == "MX":
        return {"preference": answer.preference, "exchange": str(answer.exchange).rstrip(".") or "."}
    if record_type == "SOA":
        return {
            "mname": str(answer.mname).rstrip("."),
            "rname": str(answer.rname).rstrip("."),
            "serial": answer.serial,
            "refresh": answer.refresh,
            "retry": answer.retry,
            "expire": answer.expire,
            "minimum": answer.minimum,
        }
    if record_type == "TXT":
        return "".join(part.decode("utf-8", errors="replace") for part in answer.strings)
    if record_type == "CAA":
        return {"flags": answer.flags, "tag": answer.tag.decode(), "value": answer.value.decode()}
    return answer.to_text().rstrip(".")


def get_dns_records(
    domain: str,
    record_type: Optional[str] = None,
    use_library: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    if not is_valid_domain(domain):
        return {"status": "error", "error": f"Invalid domain format: {domain}", "records": {}, "queries": {}}

    record_types = [record_type.upper()] if record_type else DNS_RECORD_TYPES
    records: Dict[str, List[Any]] = {}
    queries: Dict[str, Dict[str, Any]] = {}

    for current_type in record_types:
        query = resolve_dns_python(domain, current_type, timeout=timeout)
        queries[current_type] = query
        if query["records"]:
            records[current_type] = query["records"]

    return {"status": "ok", "records": records, "queries": queries}


def get_all_dns_info(domain: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    dns_result = get_dns_records(domain, None, use_library, timeout)
    records = dns_result.get("records", {})

    result: Dict[str, Any] = {
        "domain": domain,
        "status": dns_result.get("status", "ok"),
        "records": records,
        "queries": dns_result.get("queries", {}),
    }

    result["ip_addresses"] = list(dict.fromkeys((records.get("A") or []) + (records.get("AAAA") or [])))
    result["nameservers"] = records.get("NS", [])
    result["mail_servers"] = records.get("MX", [])

    dmarc = resolve_dns_python(f"_dmarc.{domain}", "TXT", timeout=timeout)
    result["dmarc"] = dmarc

    return result
