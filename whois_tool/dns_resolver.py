import logging
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import dns.reversename

from whois_tool.utils import execute_shell_command, is_valid_domain

logger = logging.getLogger("whodis")

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "SRV", "CAA", "DS", "DNSKEY"]


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
    if record_type == "SRV":
        return {
            "priority": answer.priority,
            "weight": answer.weight,
            "port": answer.port,
            "target": str(answer.target).rstrip(".") or ".",
        }
    return answer.to_text().rstrip(".")


def resolve_dns_command(domain: str, record_type: str, timeout: int = 10) -> Dict[str, Any]:
    output = execute_shell_command(["dig", "+short", domain, record_type], timeout=timeout)
    if output.startswith("ERROR"):
        return {"status": "error", "source": "dig", "records": [], "error": output}

    records = [
        format_dig_answer(line.strip(), record_type)
        for line in output.splitlines()
        if line.strip()
    ]
    return {"status": "ok" if records else "no_answer", "source": "dig", "records": records}


def format_dig_answer(line: str, record_type: str) -> Any:
    if record_type == "MX":
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            return {"preference": int(parts[0]), "exchange": parts[1].rstrip(".") or "."}
    if record_type == "SRV":
        parts = line.split()
        if len(parts) >= 4 and all(part.isdigit() for part in parts[:3]):
            return {
                "priority": int(parts[0]),
                "weight": int(parts[1]),
                "port": int(parts[2]),
                "target": parts[3].rstrip(".") or ".",
            }
    return line.rstrip(".")


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
        if use_library:
            query = resolve_dns_python(domain, current_type, timeout=timeout)
            if query.get("status") in {"error", "timeout", "no_nameservers"}:
                fallback = resolve_dns_command(domain, current_type, timeout=timeout)
                fallback["library_error"] = query
                query = fallback
        else:
            query = resolve_dns_command(domain, current_type, timeout=timeout)
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

    ptr_records = get_ptr_records(result["ip_addresses"], use_library=use_library, timeout=timeout)
    if ptr_records:
        result["records"]["PTR"] = ptr_records

    dmarc = (
        resolve_dns_python(f"_dmarc.{domain}", "TXT", timeout=timeout)
        if use_library
        else resolve_dns_command(f"_dmarc.{domain}", "TXT", timeout=timeout)
    )
    result["dmarc"] = dmarc

    return result


def get_ptr_records(ip_addresses: List[str], use_library: bool = True, timeout: int = 10) -> Dict[str, List[str]]:
    ptr_records: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(max(timeout / 2, 1), timeout)
    resolver.lifetime = timeout

    for ip in dict.fromkeys(ip_addresses):
        if use_library:
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(reverse_name, "PTR", lifetime=timeout, raise_on_no_answer=True)
                records = [answer.to_text().rstrip(".") for answer in answers]
            except Exception:
                records = resolve_ptr_command(ip, timeout=timeout)
        else:
            records = resolve_ptr_command(ip, timeout=timeout)

        if records:
            ptr_records[ip] = records

    return ptr_records


def resolve_ptr_command(ip: str, timeout: int = 10) -> List[str]:
    output = execute_shell_command(["dig", "+short", "-x", ip], timeout=timeout)
    if output.startswith("ERROR"):
        return []
    return [line.strip().rstrip(".") for line in output.splitlines() if line.strip()]
