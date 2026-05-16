import logging
from typing import Any, Dict, List, Optional

from ipwhois import IPWhois

from whois_tool.utils import extract_from_text, get_hosting_provider_map, is_valid_ip

logger = logging.getLogger("whodis")

def get_ip_whois_library(ip: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Get WHOIS information for an IP address using ipwhois library
    
    Args:
        ip: IP address to look up
        
    Returns:
        Dictionary of IP WHOIS information
    """
    try:
        if not is_valid_ip(ip):
            logger.warning(f"Invalid IP format: {ip}")
            return {"status": "error", "source": "ip_rdap", "error": f"Invalid IP format: {ip}", "ip": ip}
            
        obj = IPWhois(ip, timeout=timeout)
        results = obj.lookup_rdap(depth=0, retry_count=1, rate_limit_timeout=timeout)
        
        # Extract the most relevant information
        network = results.get('network', {})
        asn = results.get('asn')
        asn_description = results.get('asn_description')
        
        # Get the organization name from various possible locations
        org_name = None
        if results.get('network', {}).get('name'):
            org_name = results.get('network', {}).get('name')
        elif results.get('objects'):
            for obj_key in results.get('objects', {}):
                obj = results.get('objects', {}).get(obj_key, {})
                if obj.get('contact', {}).get('name'):
                    org_name = obj.get('contact', {}).get('name')
                    break
                    
        # Extract hosting provider
        hosting_provider = detect_hosting_provider(asn_description or "", org_name or "", asn or "")
        
        return {
            "status": "ok",
            "source": "ip_rdap",
            "ip": ip,
            "asn": asn,
            "asn_description": asn_description,
            "organization": org_name,
            "network_name": network.get('name'),
            "network_cidr": network.get('cidr'),
            "network_start_address": network.get('start_address'),
            "network_end_address": network.get('end_address'),
            "country": network.get('country'),
            "hosting_provider": hosting_provider,
        }
    except Exception as e:
        logger.error(f"Error getting IP WHOIS for {ip}: {str(e)}")
        return {"status": "error", "source": "ip_rdap", "error": str(e), "ip": ip}

def get_ip_whois_command(ip: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Get WHOIS information for an IP address using whois command
    
    Args:
        ip: IP address to look up
        timeout: Command timeout in seconds
        
    Returns:
        Dictionary of IP WHOIS information
    """
    try:
        if not is_valid_ip(ip):
            logger.warning(f"Invalid IP format: {ip}")
            return {"status": "error", "source": "whois", "error": f"Invalid IP format: {ip}", "ip": ip}
            
        import subprocess

        completed = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        raw_data = completed.stdout or completed.stderr
        
        # Extract key information using regex patterns
        org_name = extract_from_text(raw_data, r"(?:OrgName|org-name|owner|Organization):\s+(.+)") or \
                   extract_from_text(raw_data, r"(?:descr):\s+(.+)")
                   
        netname = extract_from_text(raw_data, r"(?:NetName|network:name):\s+(.+)")
        asn = extract_from_text(raw_data, r"(?:OriginAS|Origin):\s+(.+)") or \
              extract_from_text(raw_data, r"(?:ASNumber):\s+(.+)")
        
        if asn and asn.startswith("AS"):
            asn = asn[2:]  # Remove "AS" prefix
            
        cidr = extract_from_text(raw_data, r"(?:CIDR|Network):\s+(.+)")
        country = extract_from_text(raw_data, r"(?:Country|country):\s+(.+)")
        
        # Extract hosting provider based on found information
        hosting_provider = detect_hosting_provider(netname or "", org_name or "", asn or "")
        
        return {
            "status": "ok",
            "source": "whois",
            "ip": ip,
            "organization": org_name,
            "network_name": netname,
            "asn": asn,
            "cidr": cidr,
            "country": country,
            "hosting_provider": hosting_provider,
            "raw": raw_data
        }
    except Exception as e:
        logger.error(f"Error getting IP WHOIS for {ip} using command: {str(e)}")
        return {"status": "error", "source": "whois", "error": str(e), "ip": ip}

def detect_hosting_provider(netname: str, org_name: str, asn: str) -> Optional[str]:
    """
    Detect hosting provider based on network name, organization name, and ASN
    
    Args:
        netname: Network name from WHOIS
        org_name: Organization name from WHOIS
        asn: Autonomous System Number
        
    Returns:
        Detected hosting provider name or None
    """
    # Get our mapping of hosting providers to their identifiers
    provider_map = get_hosting_provider_map()
    
    # Combine all the fields we want to search in
    search_text = f"{netname} {org_name} AS{asn}".upper()
    
    # Look for each provider's identifiers in the search text
    for provider, identifiers in provider_map.items():
        for identifier in identifiers:
            if identifier.upper() in search_text:
                return provider
                
    # If we found an ASN but no provider match, we can return a generic result
    if asn:
        return f"AS{asn}"
        
    # Return None if we couldn't identify the provider
    return None

def get_ip_info(ip: str, use_library: bool = True, timeout: int = 10) -> Dict[str, Any]:
    """
    Get WHOIS information for an IP address
    
    Args:
        ip: IP address to look up
        use_library: Whether to use ipwhois library (True) or whois command (False)
        timeout: Command timeout in seconds (only used with command option)
        
    Returns:
        Dictionary of IP WHOIS information
    """
    if use_library:
        try:
            return get_ip_whois_library(ip, timeout)
        except Exception as e:
            logger.warning(f"Error using ipwhois library, falling back to whois command: {str(e)}")
            return get_ip_whois_command(ip, timeout)
    else:
        return get_ip_whois_command(ip, timeout)

def get_ip_info_for_domain(domain: str, ip_addresses: List[str], use_library: bool = True, timeout: int = 10) -> Dict[str, Dict[str, Any]]:
    """
    Get WHOIS information for all IP addresses associated with a domain
    
    Args:
        domain: Domain name for reference
        ip_addresses: List of IP addresses to look up
        use_library: Whether to use ipwhois library (True) or whois command (False)
        timeout: Command timeout in seconds (only used with command option)
        
    Returns:
        Dictionary mapping IP addresses to their WHOIS information
    """
    result = {}

    for ip in dict.fromkeys(ip_addresses):
        result[ip] = get_ip_info(ip, use_library, timeout)

    return {
        "domain": domain,
        "status": "ok",
        "addresses": result,
    }
