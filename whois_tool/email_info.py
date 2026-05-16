import logging
import shlex
from typing import Any, Dict, List, Optional, Tuple

import requests

from whois_tool.dns_resolver import get_ptr_records, resolve_dns_command, resolve_dns_python

logger = logging.getLogger("whodis")

EMAIL_USER_AGENT = "whodis/0.3"
DNS_FALLBACK_STATUSES = {"error", "timeout", "no_nameservers"}
SPF_DNS_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
SPF_DNS_MODIFIERS = {"redirect"}


def get_email_info(
    domain: str,
    dns_info: Optional[Dict[str, Any]] = None,
    use_library: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "status": "ok",
        "mx": get_mx_info(domain, dns_info=dns_info, use_library=use_library, timeout=timeout),
        "spf": get_spf_info(domain, dns_info=dns_info, use_library=use_library, timeout=timeout),
        "dmarc": get_dmarc_info(domain, dns_info=dns_info, use_library=use_library, timeout=timeout),
        "mta_sts": get_mta_sts_info(domain, use_library=use_library, timeout=timeout),
        "tls_rpt": get_tls_rpt_info(domain, use_library=use_library, timeout=timeout),
        "bimi": get_bimi_info(domain, use_library=use_library, timeout=timeout),
        "warnings": [],
    }

    for section in ("mx", "spf", "dmarc", "mta_sts", "tls_rpt", "bimi"):
        for warning in result[section].get("warnings", []):
            result["warnings"].append(f"{section}: {warning}")

    if result["warnings"]:
        result["status"] = "ok_with_warnings"
    return result


def get_mx_info(
    domain: str,
    dns_info: Optional[Dict[str, Any]] = None,
    use_library: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    source, records = _records_from_dns_info(dns_info, "MX")
    query: Optional[Dict[str, Any]] = None
    if records is None:
        source = "query"
        query = _resolve_dns(domain, "MX", use_library=use_library, timeout=timeout)
        records = query.get("records", [])

    mx_records = normalize_mx_records(records or [])
    result: Dict[str, Any] = {
        "status": "ok",
        "source": source,
        "records": mx_records,
        "null_mx": False,
        "hosts": [],
        "warnings": [],
    }
    if query:
        result["query_status"] = query.get("status")
        if query.get("error"):
            result["query_error"] = query.get("error")

    if not mx_records:
        result["status"] = "missing"
        result["warnings"].append("No MX records found; inbound SMTP may fall back to A/AAAA.")
        return result

    null_mx_records = [record for record in mx_records if record["exchange"] == "."]
    if null_mx_records:
        result["null_mx"] = True
        if len(mx_records) == 1:
            result["status"] = "null_mx"
            return result
        result["warnings"].append("Null MX is published alongside other MX records.")

    for record in mx_records:
        exchange = record["exchange"]
        if exchange == ".":
            continue
        host = resolve_mx_host(exchange, use_library=use_library, timeout=timeout)
        host["preference"] = record.get("preference")
        result["hosts"].append(host)

    if not result["hosts"] and not result["null_mx"]:
        result["warnings"].append("MX records did not contain usable hostnames.")
    for host in result["hosts"]:
        result["warnings"].extend(host.get("warnings", []))
    return result


def normalize_mx_records(records: List[Any]) -> List[Dict[str, Any]]:
    normalized = []
    for record in records:
        preference = None
        exchange = None
        if isinstance(record, dict):
            preference = record.get("preference")
            exchange = record.get("exchange")
        else:
            parts = str(record).split()
            if len(parts) >= 2 and parts[0].isdigit():
                preference = int(parts[0])
                exchange = parts[1]
            elif parts:
                exchange = parts[-1]

        if exchange is None:
            continue
        exchange = str(exchange).strip().rstrip(".").lower() or "."
        if exchange == "":
            exchange = "."
        normalized.append({"preference": preference, "exchange": exchange})

    return sorted(normalized, key=lambda item: (item["preference"] is None, item["preference"] or 0, item["exchange"]))


def resolve_mx_host(hostname: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    addresses: List[str] = []
    queries: Dict[str, Dict[str, Any]] = {}
    warnings: List[str] = []

    for record_type in ("A", "AAAA"):
        query = _resolve_dns(hostname, record_type, use_library=use_library, timeout=timeout)
        queries[record_type] = query
        addresses.extend(str(record) for record in query.get("records", []) if record)

    addresses = list(dict.fromkeys(addresses))
    ptr_records = get_ptr_records(addresses, use_library=use_library, timeout=timeout) if addresses else {}
    if not addresses:
        warnings.append(f"MX host {hostname} has no A/AAAA records.")
    else:
        missing_ptr = [address for address in addresses if address not in ptr_records]
        if missing_ptr:
            warnings.append(f"MX host {hostname} is missing PTR for {', '.join(missing_ptr)}.")

    return {
        "host": hostname,
        "addresses": addresses,
        "ptr": ptr_records,
        "queries": queries,
        "warnings": warnings,
    }


def get_spf_info(
    domain: str,
    dns_info: Optional[Dict[str, Any]] = None,
    use_library: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    source, txt_records = _records_from_dns_info(dns_info, "TXT")
    query: Optional[Dict[str, Any]] = None
    if txt_records is None:
        source = "query"
        query = _resolve_dns(domain, "TXT", use_library=use_library, timeout=timeout)
        txt_records = query.get("records", [])

    spf_records = _version_records(txt_records or [], "v=spf1")
    result: Dict[str, Any] = {
        "status": "ok",
        "source": source,
        "records": spf_records,
        "warnings": [],
    }
    if query:
        result["query_status"] = query.get("status")

    if not spf_records:
        result["status"] = "missing"
        result["warnings"].append("No SPF record found.")
        return result

    analyses = [parse_spf_record(record) for record in spf_records]
    result["analysis"] = analyses
    if len(spf_records) > 1:
        result["status"] = "multiple"
        result["warnings"].append("Multiple SPF records found; receivers can treat SPF as permanent error.")

    result["record"] = spf_records[0]
    result["dns_lookup_count"] = analyses[0]["dns_lookup_count"]
    result["warnings"].extend(analyses[0].get("warnings", []))
    return result


def parse_spf_record(record: str) -> Dict[str, Any]:
    terms = record.strip().split()
    mechanisms: List[Dict[str, str]] = []
    modifiers: Dict[str, str] = {}
    warnings: List[str] = []
    dns_lookup_count = 0

    for raw_term in terms[1:]:
        if not raw_term:
            continue
        qualifier = "+"
        term = raw_term
        if term[0] in "+-~?":
            qualifier = term[0]
            term = term[1:]

        if "=" in term:
            key, value = term.split("=", 1)
            key = key.lower()
            modifiers[key] = value
            if key in SPF_DNS_MODIFIERS:
                dns_lookup_count += 1
            continue

        mechanism = term.split(":", 1)[0].split("/", 1)[0].lower()
        mechanisms.append({"qualifier": qualifier, "mechanism": mechanism, "value": term})
        if mechanism in SPF_DNS_MECHANISMS:
            dns_lookup_count += 1

    if dns_lookup_count > 10:
        warnings.append(f"SPF uses {dns_lookup_count} DNS-lookup mechanisms; receivers allow 10.")
    if any(item["mechanism"] == "ptr" for item in mechanisms):
        warnings.append("SPF uses the deprecated ptr mechanism.")

    terminal = mechanisms[-1] if mechanisms else None
    if not terminal or terminal["mechanism"] != "all":
        warnings.append("SPF record does not end with an all mechanism.")
    elif terminal["qualifier"] == "+":
        warnings.append("SPF ends in +all, allowing any sender.")
    elif terminal["qualifier"] == "?":
        warnings.append("SPF ends in ?all, which is neutral and weak.")
    elif terminal["qualifier"] == "~":
        warnings.append("SPF ends in ~all; softfail is weaker than -all.")

    return {
        "version": "spf1",
        "mechanisms": mechanisms,
        "modifiers": modifiers,
        "dns_lookup_count": dns_lookup_count,
        "warnings": warnings,
    }


def get_dmarc_info(
    domain: str,
    dns_info: Optional[Dict[str, Any]] = None,
    use_library: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    query = dns_info.get("dmarc") if dns_info else None
    source = "dns_info" if query is not None else "query"
    if query is None:
        query = _resolve_dns(f"_dmarc.{domain}", "TXT", use_library=use_library, timeout=timeout)

    records = _version_records(query.get("records", []), "v=DMARC1")
    result: Dict[str, Any] = {
        "status": "ok",
        "source": source,
        "query_status": query.get("status"),
        "records": records,
        "warnings": [],
    }
    if not records:
        result["status"] = "missing"
        result["warnings"].append("No DMARC record found.")
        return result

    if len(records) > 1:
        result["status"] = "multiple"
        result["warnings"].append("Multiple DMARC records found.")

    tags = parse_tag_value_record(records[0])
    result.update(
        {
            "record": records[0],
            "tags": tags,
            "policy": tags.get("p"),
            "subdomain_policy": tags.get("sp"),
            "pct": tags.get("pct"),
            "rua": split_address_list(tags.get("rua")),
            "ruf": split_address_list(tags.get("ruf")),
            "alignment": {
                "adkim": tags.get("adkim", "r"),
                "aspf": tags.get("aspf", "r"),
            },
        }
    )
    result["warnings"].extend(dmarc_warnings(tags))
    return result


def dmarc_warnings(tags: Dict[str, str]) -> List[str]:
    warnings = []
    policy = (tags.get("p") or "").lower()
    if not policy:
        warnings.append("DMARC record is missing required p policy.")
    elif policy == "none":
        warnings.append("DMARC policy is p=none; mail is monitored but not rejected or quarantined.")

    pct = tags.get("pct")
    if pct:
        try:
            if int(pct) < 100:
                warnings.append(f"DMARC pct={pct}; policy is not applied to all mail.")
        except ValueError:
            warnings.append(f"DMARC pct={pct} is not a valid integer.")
    if not tags.get("rua"):
        warnings.append("DMARC has no aggregate reporting address (rua).")
    return warnings


def get_mta_sts_info(domain: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    query = _resolve_dns(f"_mta-sts.{domain}", "TXT", use_library=use_library, timeout=timeout)
    records = _version_records(query.get("records", []), "v=STSv1")
    result: Dict[str, Any] = {
        "status": "ok",
        "query_status": query.get("status"),
        "records": records,
        "warnings": [],
    }
    if not records:
        result["status"] = "missing"
        return result

    if len(records) > 1:
        result["status"] = "multiple"
        result["warnings"].append("Multiple MTA-STS TXT records found.")

    result["record"] = records[0]
    result["tags"] = parse_tag_value_record(records[0])
    policy_fetch = fetch_mta_sts_policy(domain, timeout=timeout)
    result["policy_fetch"] = policy_fetch
    if policy_fetch.get("status") != "ok":
        result["status"] = "policy_error"
        result["warnings"].append(f"MTA-STS TXT exists but policy fetch failed: {policy_fetch.get('error')}.")
        return result

    policy = policy_fetch.get("policy", {})
    result["policy"] = policy
    result["warnings"].extend(mta_sts_policy_warnings(policy))
    return result


def fetch_mta_sts_policy(domain: str, timeout: int = 10) -> Dict[str, Any]:
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": EMAIL_USER_AGENT})
    except requests.Timeout:
        return {"status": "timeout", "url": url, "error": "request timed out"}
    except requests.RequestException as exc:
        return {"status": "error", "url": url, "error": str(exc)}

    if response.status_code != 200:
        return {
            "status": "http_error",
            "url": url,
            "status_code": response.status_code,
            "error": f"HTTP {response.status_code}",
        }

    return {
        "status": "ok",
        "url": url,
        "status_code": response.status_code,
        "policy": parse_mta_sts_policy(response.text),
    }


def parse_mta_sts_policy(text: str) -> Dict[str, Any]:
    policy: Dict[str, Any] = {}
    mx_hosts: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            mx_hosts.append(value)
        else:
            policy[key] = value

    if mx_hosts:
        policy["mx"] = mx_hosts
    if "max_age" in policy:
        try:
            policy["max_age_seconds"] = int(policy["max_age"])
        except ValueError:
            pass
    return policy


def mta_sts_policy_warnings(policy: Dict[str, Any]) -> List[str]:
    warnings = []
    required = ["version", "mode", "mx", "max_age"]
    missing = [field for field in required if not policy.get(field)]
    if missing:
        warnings.append(f"MTA-STS policy missing {', '.join(missing)}.")
    if policy.get("version") and policy.get("version") != "STSv1":
        warnings.append(f"MTA-STS policy version is {policy.get('version')}.")
    if str(policy.get("mode", "")).lower() == "none":
        warnings.append("MTA-STS mode is none; SMTP TLS policy is not enforced.")
    if policy.get("max_age") and "max_age_seconds" not in policy:
        warnings.append(f"MTA-STS max_age={policy.get('max_age')} is not a valid integer.")
    return warnings


def get_tls_rpt_info(domain: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    query = _resolve_dns(f"_smtp._tls.{domain}", "TXT", use_library=use_library, timeout=timeout)
    records = _version_records(query.get("records", []), "v=TLSRPTv1")
    result: Dict[str, Any] = {
        "status": "ok",
        "query_status": query.get("status"),
        "records": records,
        "warnings": [],
    }
    if not records:
        result["status"] = "missing"
        return result
    if len(records) > 1:
        result["status"] = "multiple"
        result["warnings"].append("Multiple TLS-RPT records found.")
    tags = parse_tag_value_record(records[0])
    result["record"] = records[0]
    result["tags"] = tags
    result["rua"] = split_address_list(tags.get("rua"))
    return result


def get_bimi_info(domain: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    query = _resolve_dns(f"default._bimi.{domain}", "TXT", use_library=use_library, timeout=timeout)
    records = _version_records(query.get("records", []), "v=BIMI1")
    result: Dict[str, Any] = {
        "status": "ok",
        "query_status": query.get("status"),
        "records": records,
        "warnings": [],
    }
    if not records:
        result["status"] = "missing"
        return result
    if len(records) > 1:
        result["status"] = "multiple"
        result["warnings"].append("Multiple BIMI records found.")
    result["record"] = records[0]
    result["tags"] = parse_tag_value_record(records[0])
    return result


def parse_tag_value_record(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def split_address_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _resolve_dns(domain: str, record_type: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    if use_library:
        query = resolve_dns_python(domain, record_type, timeout=timeout)
        if query.get("status") in DNS_FALLBACK_STATUSES:
            fallback = resolve_dns_command(domain, record_type, timeout=timeout)
            fallback["library_error"] = query
            return fallback
        return query
    return resolve_dns_command(domain, record_type, timeout=timeout)


def _records_from_dns_info(dns_info: Optional[Dict[str, Any]], record_type: str) -> Tuple[str, Optional[List[Any]]]:
    if not dns_info or dns_info.get("status") == "skipped":
        return "query", None
    records = dns_info.get("records", {})
    queries = dns_info.get("queries", {})
    if record_type in records:
        return "dns_info", records.get(record_type, [])
    if record_type in queries:
        return "dns_info", []
    return "query", None


def _version_records(records: List[Any], version: str) -> List[str]:
    version_lower = version.lower()
    return [
        record
        for record in (_normalize_txt_record(value) for value in records)
        if record.lower().startswith(version_lower)
    ]


def _normalize_txt_record(value: Any) -> str:
    text = str(value).strip()
    if '"' not in text:
        return text
    try:
        return "".join(shlex.split(text))
    except ValueError:
        return text.strip('"')
