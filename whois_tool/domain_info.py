import logging
import subprocess
from typing import Any, Dict

from whois_tool.rdap import lookup_domain_rdap
from whois_tool.utils import extract_all_from_text, extract_from_text, is_valid_domain

logger = logging.getLogger("whodis")


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


def get_domain_whois(
    domain: str,
    use_library: bool = True,
    timeout: int = 10,
    allow_legacy_whois: bool = True,
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

    rdap_result = lookup_domain_rdap(domain, timeout=timeout)
    if rdap_result.get("status") in {"ok", "not_found"}:
        return rdap_result

    if allow_legacy_whois:
        whois_result = get_domain_whois_command(domain, timeout)
        whois_result["rdap_error"] = rdap_result
        return whois_result

    return rdap_result
