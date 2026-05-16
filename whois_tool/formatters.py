import csv
import io
import json
import logging
from typing import Any, Dict, Iterable, List, Optional

from colorama import Fore, Style, init

init()

logger = logging.getLogger("whodis")


class TextFormatter:
    @staticmethod
    def format_complete_domain_info(
        domain_whois: Dict[str, Any],
        dns_info: Dict[str, Any],
        ip_info: Dict[str, Any],
        redirect_info: Optional[Dict[str, Any]] = None,
        ssl_info: Optional[Dict[str, Any]] = None,
        input_info: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        sections = []
        if input_info:
            sections.append(TextFormatter.format_input(input_info))
        sections.append(TextFormatter.format_registration(domain_whois))
        if dns_info:
            sections.append(TextFormatter.format_dns_records(dns_info))
        if ip_info:
            sections.append(TextFormatter.format_ip_info(ip_info))
        if ssl_info:
            sections.append(TextFormatter.format_tls_info(ssl_info))
        if redirect_info:
            sections.append(TextFormatter.format_redirect_info(redirect_info))
        return "\n\n".join(section for section in sections if section)

    @staticmethod
    def format_input(data: Dict[str, Any]) -> str:
        lines = [heading(f"whodis: {data.get('display_domain') or data.get('domain')}")]
        if data.get("original") != data.get("domain"):
            lines.append(label("Input", data.get("original")))
        if data.get("idna"):
            lines.append(label("IDNA", data.get("domain")))
        return "\n".join(lines)

    @staticmethod
    def format_registration(data: Dict[str, Any]) -> str:
        lines = [heading("Registration")]
        status = data.get("status", "unknown")
        lines.append(label("Source", data.get("source", "rdap")))
        lines.append(label("Status", status))

        if status != "ok":
            if data.get("error"):
                lines.append(warn(data["error"]))
            if data.get("rdap_error", {}).get("error"):
                lines.append(warn(f"RDAP: {data['rdap_error']['error']}"))
            return "\n".join(lines)

        lines.extend(
            compact_lines(
                [
                    label("Domain", data.get("domain")),
                    label("Registrar", registrar_name(data)),
                    label("IANA Registrar ID", nested(data, "registrar", "iana_id")),
                    label("Created", data.get("created")),
                    label("Expires", data.get("expires")),
                    label("Last Changed", data.get("last_changed")),
                    label("RDAP Updated", data.get("rdap_updated")),
                    label("RDAP URL", data.get("query_url")),
                ]
            )
        )

        if data.get("statuses"):
            lines.append(label("Domain Status", ", ".join(data["statuses"])))
        if data.get("nameservers"):
            lines.append(label("Nameservers", ", ".join(data["nameservers"])))
        raw_fields = data.get("raw_fields") or {}
        if raw_fields:
            lines.extend(TextFormatter.format_extra_whois_fields(raw_fields))
        if data.get("secure_dns"):
            signed = data["secure_dns"].get("delegationSigned")
            lines.append(label("DNSSEC", "signed" if signed else "not signed"))
        if data.get("redacted"):
            lines.append(label("Redaction", "RDAP response indicates redacted fields"))
        return "\n".join(lines)

    @staticmethod
    def format_extra_whois_fields(data: Dict[str, Any]) -> List[str]:
        field_names = [
            "whois_server",
            "dnssec",
            "emails",
            "name",
            "org",
            "address",
            "city",
            "state",
            "registrant_postal_code",
            "country",
            "registrant_name",
            "registrant_organization",
            "admin_name",
            "admin_email",
            "tech_name",
            "tech_email",
        ]
        lines = []
        for field in field_names:
            value = data.get(field)
            if value in (None, "", []):
                continue
            lines.append(label(field.replace("_", " ").title(), format_list_value(value)))
        return lines

    @staticmethod
    def format_dns_records(data: Dict[str, Any]) -> str:
        lines = [heading("DNS")]
        if data.get("status") == "skipped":
            return "\n".join(lines + [label("Status", "skipped")])
        records = data.get("records", {})
        if not records:
            return "\n".join(lines + [warn("No DNS records found")])

        for record_type, values in records.items():
            if record_type == "PTR" and isinstance(values, dict):
                lines.append(label("PTR", "reverse DNS"))
                for ip, ptr_values in values.items():
                    lines.append(f"  {ip}: {', '.join(format_record_value(value) for value in ptr_values)}")
                continue
            lines.append(label(record_type, ""))
            for value in values:
                lines.append(f"  - {format_record_value(value)}")
        dmarc_records = data.get("dmarc", {}).get("records") or []
        if dmarc_records:
            lines.append(label("DMARC", ", ".join(format_record_value(value) for value in dmarc_records)))
        return "\n".join(lines)

    @staticmethod
    def format_ip_info(data: Dict[str, Any]) -> str:
        addresses = data.get("addresses", data)
        if not addresses:
            return ""

        lines = [heading("IP Ownership")]
        for ip, info in addresses.items():
            if info.get("status") != "ok":
                lines.append(label(ip, info.get("error", info.get("status"))))
                continue
            lines.append(label(ip, info.get("hosting_provider") or info.get("organization") or "resolved"))
            for field, display in [
                ("organization", "Organization"),
                ("network_name", "Network Name"),
                ("asn", "ASN"),
                ("asn_description", "ASN Description"),
                ("network_cidr", "Network CIDR"),
                ("network_start_address", "Network Start"),
                ("network_end_address", "Network End"),
                ("country", "Country"),
            ]:
                value = info.get(field)
                if value:
                    if field == "asn" and not str(value).startswith("AS"):
                        value = f"AS{value}"
                    lines.append(f"  {display}: {value}")
        return "\n".join(lines)

    @staticmethod
    def format_tls_info(data: Dict[str, Any]) -> str:
        lines = [heading("TLS")]
        lines.append(label("Status", data.get("status")))
        if not data.get("has_tls"):
            if data.get("error"):
                lines.append(warn(data["error"]))
            return "\n".join(lines)
        lines.extend(
            compact_lines(
                [
                    label("Verified", str(data.get("verified")).lower()),
                    label("Common Name", data.get("common_name")),
                    label("Issuer", data.get("issuer_organization") or data.get("issuer_common_name")),
                    label("Organization", data.get("organization")),
                    label("Organizational Unit", data.get("organizational_unit")),
                    label("Valid Until", data.get("valid_until")),
                    label("Days Remaining", data.get("days_remaining")),
                    label("TLS Version", data.get("tls_version")),
                    label("Cipher", data.get("cipher")),
                    label("SHA256 Fingerprint", data.get("fingerprint_sha256")),
                ]
            )
        )
        if data.get("subject_alt_names"):
            lines.append(label("Subject Alt Names", ", ".join(data["subject_alt_names"])))
        if data.get("verification_error"):
            lines.append(warn(data["verification_error"]))
        return "\n".join(lines)

    @staticmethod
    def format_redirect_info(data: Dict[str, Any]) -> str:
        lines = [heading("HTTP")]
        if data.get("protocols"):
            for scheme in ("https", "http"):
                protocol_data = data["protocols"].get(scheme)
                if protocol_data:
                    lines.extend(TextFormatter.format_single_redirect(scheme.upper(), protocol_data))
            return "\n".join(lines)

        lines.append(label("Status", data.get("status")))
        if data.get("error") and data.get("status") != "ok":
            lines.append(warn(data["error"]))
            return "\n".join(lines)
        lines.extend(
            compact_lines(
                [
                    label("Initial URL", data.get("initial_url")),
                    label("Final URL", data.get("final_url")),
                    label("HTTP Status", data.get("status_code")),
                    label("Redirects", str(data.get("redirects")).lower()),
                ]
            )
        )
        if data.get("redirect_chain"):
            lines.append(label("Chain", " -> ".join(data["redirect_chain"])))
        return "\n".join(lines)

    @staticmethod
    def format_single_redirect(name: str, data: Dict[str, Any]) -> List[str]:
        lines = [label(name, data.get("status"))]
        if data.get("error") and data.get("status") != "ok":
            lines.append(f"  Error: {data['error']}")
            return lines
        lines.extend(
            compact_lines(
                [
                    f"  Method: {data.get('method')}",
                    f"  Initial URL: {data.get('initial_url')}",
                    f"  Final URL: {data.get('final_url')}",
                    f"  Status Code: {data.get('status_code')}",
                    f"  Redirects: {str(data.get('redirects')).lower()}",
                    f"  Redirect Count: {data.get('redirect_count')}",
                    f"  Domain Changed: {str(data.get('domain_changed')).lower()}",
                ]
            )
        )
        if data.get("redirect_chain"):
            lines.append(f"  Chain: {' -> '.join(data['redirect_chain'])}")
        return lines

    @staticmethod
    def format_redirect_only(data: Dict[str, Any]) -> str:
        return TextFormatter.format_redirect_info(data)


class JSONFormatter:
    @staticmethod
    def format_complete_domain_info(
        domain_whois: Dict[str, Any],
        dns_info: Dict[str, Any],
        ip_info: Dict[str, Any],
        redirect_info: Optional[Dict[str, Any]] = None,
        ssl_info: Optional[Dict[str, Any]] = None,
        input_info: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload: Dict[str, Any] = {
            "input": input_info or {},
            "registration": domain_whois,
            "dns": dns_info,
            "ip": ip_info,
            "tls": ssl_info or {},
            "http": redirect_info or {},
            "meta": meta or {},
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    @staticmethod
    def format_redirect_only(data: Dict[str, Any]) -> str:
        return json.dumps({"http": data}, indent=2, sort_keys=True)


class CSVFormatter:
    @staticmethod
    def format_complete_domain_info(
        domain_whois: Dict[str, Any],
        dns_info: Dict[str, Any],
        ip_info: Dict[str, Any],
        redirect_info: Optional[Dict[str, Any]] = None,
        ssl_info: Optional[Dict[str, Any]] = None,
        input_info: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload = {
            "input": input_info or {},
            "registration": domain_whois,
            "dns": dns_info,
            "ip": ip_info,
            "tls": ssl_info or {},
            "http": redirect_info or {},
            "meta": meta or {},
        }
        return flatten_csv(payload)

    @staticmethod
    def format_redirect_only(data: Dict[str, Any]) -> str:
        return flatten_csv({"http": data})


def get_formatter(format_type: str):
    format_type = format_type.lower()
    if format_type == "json":
        return JSONFormatter
    if format_type == "csv":
        return CSVFormatter
    return TextFormatter


def output_result(result: str, output_file: Optional[str] = None) -> None:
    if output_file:
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(result)
    else:
        print(result)


def heading(text: str) -> str:
    return f"{Fore.GREEN}== {text} =={Style.RESET_ALL}"


def label(name: str, value: Any) -> str:
    return f"{Fore.CYAN}{name}:{Style.RESET_ALL} {value}"


def warn(text: str) -> str:
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"


def nested(data: Dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def registrar_name(data: Dict[str, Any]) -> Any:
    registrar = data.get("registrar")
    if isinstance(registrar, dict):
        return registrar.get("name")
    return registrar


def format_list_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, tuple):
        return ", ".join(str(item) for item in value)
    return str(value)


def compact_lines(lines: Iterable[Optional[str]]) -> List[str]:
    return [line for line in lines if line and not line.endswith(" None")]


def format_record_value(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key}={item}" for key, item in value.items())
    return str(value)


def flatten_csv(payload: Dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["path", "value"])
    for path, value in flatten(payload):
        if path.endswith(".raw"):
            continue
        writer.writerow([path, value])
    return output.getvalue()


def flatten(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flatten(item, f"{prefix}.{key}" if prefix else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from flatten(item, f"{prefix}[{index}]")
    else:
        yield prefix, value
