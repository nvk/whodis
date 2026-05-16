import logging
import subprocess
from datetime import date, datetime
from typing import Any, Dict

from whois_tool.rdap import lookup_domain_rdap
from whois_tool.utils import extract_all_from_text, extract_from_text, is_valid_domain

logger = logging.getLogger("whodis")

try:
    import whois as python_whois
except ImportError:  # pragma: no cover - exercised when optional dependency is absent
    python_whois = None
else:
    if not hasattr(python_whois, "whois"):
        python_whois = None


def get_domain_whois_command(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Get WHOIS information for a domain using whois command line tool
    
    Args:
        domain: Domain name to look up
        timeout: Command timeout in seconds
        
    Returns:
        Dictionary of WHOIS information
    """
    if not is_valid_domain(domain):
        logger.warning(f"Invalid domain format: {domain}")
        return {"error": f"Invalid domain format: {domain}"}
        
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"status": "unavailable", "source": "whois", "error": "whois command not found"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "source": "whois", "error": f"whois timed out after {timeout}s"}
    except Exception as exc:
        return {"status": "error", "source": "whois", "error": str(exc)}

    raw_data = result.stdout or result.stderr
    if result.returncode != 0 and not raw_data:
        return {"status": "error", "source": "whois", "error": f"whois exited {result.returncode}"}
    
    # Extract key information using regex patterns
    registrar = extract_from_text(raw_data, r"Registrar:[^\n]*\s+(.+)")
    created_date = extract_from_text(raw_data, r"Creation Date:[^\n]*\s+(.+)")
    updated_date = extract_from_text(raw_data, r"Updated Date:[^\n]*\s+(.+)")
    expiration_date = extract_from_text(raw_data, r"Registrar Registration Expiration Date:[^\n]*\s+(.+)") or \
                      extract_from_text(raw_data, r"Registry Expiry Date:[^\n]*\s+(.+)") or \
                      extract_from_text(raw_data, r"Expiration Date:[^\n]*\s+(.+)")
    
    name_servers = extract_all_from_text(raw_data, r"Name Server:[^\n]*\s+(.+)")
    status = extract_all_from_text(raw_data, r"Status:[^\n]*\s+(.+)")
    
    # Create structured result
    result = {
        "status": "ok",
        "source": "whois",
        "domain": domain,
        "registrar": registrar,
        "created": created_date,
        "last_changed": updated_date,
        "expires": expiration_date,
        "name_servers": name_servers,
        "statuses": status,
        "raw": raw_data,
    }

    return result


def get_domain_whois_python_whois(domain: str) -> Dict[str, Any]:
    if not is_valid_domain(domain):
        logger.warning(f"Invalid domain format: {domain}")
        return {"status": "error", "source": "python-whois", "error": f"Invalid domain format: {domain}"}

    if python_whois is None:
        return {"status": "unavailable", "source": "python-whois", "error": "python-whois is not installed"}

    try:
        domain_info = python_whois.whois(domain)
    except Exception as exc:
        logger.error("Error getting WHOIS for %s with python-whois: %s", domain, exc)
        return {"status": "error", "source": "python-whois", "error": str(exc)}

    fields = _serialize_whois_fields(domain_info)
    result: Dict[str, Any] = {
        "status": "ok",
        "source": "python-whois",
        "domain": fields.get("domain_name") or fields.get("domain") or domain,
        "registrar": fields.get("registrar"),
        "created": fields.get("creation_date"),
        "last_changed": fields.get("updated_date"),
        "expires": fields.get("expiration_date"),
        "name_servers": _as_list(fields.get("name_servers")),
        "statuses": _as_list(fields.get("status")),
        "raw_fields": fields,
    }

    return result


def get_domain_whois(
    domain: str,
    use_library: bool = True,
    timeout: int = 10,
    allow_legacy_whois: bool = True,
    prefer_python_whois: bool = False,
) -> Dict[str, Any]:
    """
    Get WHOIS information for a domain using either python-whois or command line
    
    Args:
        domain: Domain name to look up
        use_library: Whether to use python-whois library (True) or command line tool (False)
        timeout: Command timeout in seconds (only used with command line option)
        
    Returns:
        Dictionary of WHOIS information
    """
    if not is_valid_domain(domain):
        logger.warning(f"Invalid domain format: {domain}")
        return {"status": "error", "source": "input", "error": f"Invalid domain format: {domain}"}

    if not use_library:
        return get_domain_whois_command(domain, timeout)

    if prefer_python_whois:
        python_result = get_domain_whois_python_whois(domain)
        if python_result.get("status") == "ok":
            return python_result
        command_result = get_domain_whois_command(domain, timeout)
        command_result["python_whois_error"] = python_result
        return command_result

    rdap_result = lookup_domain_rdap(domain, timeout=timeout)
    if rdap_result.get("status") in {"ok", "not_found"}:
        return rdap_result

    if allow_legacy_whois:
        python_result = get_domain_whois_python_whois(domain)
        if python_result.get("status") == "ok":
            python_result["rdap_error"] = rdap_result
            return python_result
        whois_result = get_domain_whois_command(domain, timeout)
        whois_result["rdap_error"] = rdap_result
        if python_result.get("status") != "unavailable":
            whois_result["python_whois_error"] = python_result
        return whois_result

    return rdap_result


def _serialize_whois_fields(domain_info: Any) -> Dict[str, Any]:
    if hasattr(domain_info, "items"):
        items = domain_info.items()
    elif hasattr(domain_info, "__dict__"):
        items = domain_info.__dict__.items()
    else:
        items = []

    return {str(key): _serialize_whois_value(value) for key, value in items if not str(key).startswith("_")}


def _serialize_whois_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_whois_value(item) for item in value]
    if isinstance(value, tuple):
        return [_serialize_whois_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize_whois_value(item) for key, item in value.items()}
    return value


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]
