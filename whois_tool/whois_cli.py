#!/usr/bin/env python3

import logging
import os
import sys
from contextlib import nullcontext
from typing import Optional

import click

from whois_tool import __version__
from whois_tool.dns_resolver import get_all_dns_info
from whois_tool.domain_info import get_domain_whois
from whois_tool.email_info import get_email_info
from whois_tool.formatters import get_formatter, output_result
from whois_tool.ip_info import get_ip_info_for_domain
from whois_tool.rdap import utc_now_iso
from whois_tool.spinner import spinning_cursor
from whois_tool.utils import check_domain_redirect, get_ssl_certificate_info, normalize_domain_input

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("whodis")


@click.command()
@click.argument("target", required=True)
@click.option(
    "--format",
    "-f",
    "output_format",
    default="text",
    type=click.Choice(["text", "json", "csv"], case_sensitive=False),
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), help="Output file. Defaults to stdout.")
@click.option("--no-dns", is_flag=True, help="Skip DNS lookups.")
@click.option("--no-email", is_flag=True, help="Skip email posture checks.")
@click.option("--no-ip", is_flag=True, help="Skip IP RDAP lookups for resolved addresses.")
@click.option("--no-tls", "--no-ssl", is_flag=True, help="Skip TLS certificate inspection.")
@click.option("--no-whois-fallback", is_flag=True, help="Do not fall back to legacy WHOIS when RDAP fails.")
@click.option("--whois", "force_whois", is_flag=True, help="Use the legacy WHOIS command instead of RDAP.")
@click.option("--python-whois", is_flag=True, help="Use the python-whois library as the registration source.")
@click.option("--timeout", type=int, default=10, show_default=True, help="Per-section timeout in seconds.")
@click.option("--check-redirect", is_flag=True, help="Check HTTP/HTTPS redirects.")
@click.option("--no-spinner", is_flag=True, help="Disable the loading spinner.")
@click.option("--use-command-line", is_flag=True, help="Use command-line tools for WHOIS, DNS, and IP lookups.")
@click.option("--verbose", "-v", count=True, help="Increase verbosity.")
@click.version_option(__version__, prog_name="whodis")
def main(
    target: str,
    output_format: str,
    output: Optional[str],
    no_dns: bool,
    no_email: bool,
    no_ip: bool,
    no_tls: bool,
    no_whois_fallback: bool,
    force_whois: bool,
    python_whois: bool,
    timeout: int,
    check_redirect: bool,
    no_spinner: bool,
    use_command_line: bool,
    verbose: int,
) -> None:
    """Inspect domain registration, DNS, email posture, IP ownership, TLS, and redirects."""
    configure_logging(verbose)

    if os.environ.get("WHODIS_NO_SPINNER"):
        no_spinner = True

    normalized = normalize_domain_input(target)
    if not normalized.get("valid"):
        click.echo(f"Error: invalid domain input: {target}", err=True)
        if normalized.get("error"):
            click.echo(normalized["error"], err=True)
        sys.exit(1)

    domain = normalized["domain"]
    dns_ip_use_library = not use_command_line
    registration_use_library = not (force_whois or use_command_line)
    meta = {
        "tool": "whodis",
        "version": __version__,
        "timestamp": utc_now_iso(),
        "timeout": timeout,
    }

    try:
        with maybe_spinner(f"Getting registration data for {domain}...", no_spinner):
            registration = get_domain_whois(
                domain,
                use_library=registration_use_library,
                timeout=timeout,
                allow_legacy_whois=not no_whois_fallback,
                prefer_python_whois=python_whois,
            )

        dns_info = {"domain": domain, "status": "skipped", "records": {}, "queries": {}}
        if not no_dns:
            with maybe_spinner(f"Getting DNS records for {domain}...", no_spinner):
                dns_info = get_all_dns_info(domain, use_library=dns_ip_use_library, timeout=timeout)

        email_info = {"domain": domain, "status": "skipped"}
        if not no_email and not no_dns:
            with maybe_spinner(f"Checking email posture for {domain}...", no_spinner):
                email_info = get_email_info(
                    domain,
                    dns_info=dns_info,
                    use_library=dns_ip_use_library,
                    timeout=timeout,
                )

        ip_info = {"domain": domain, "status": "skipped", "addresses": {}}
        if not no_ip and dns_info.get("ip_addresses"):
            with maybe_spinner(f"Getting IP ownership for {domain}...", no_spinner):
                ip_info = get_ip_info_for_domain(
                    domain,
                    dns_info.get("ip_addresses", []),
                    use_library=dns_ip_use_library,
                    timeout=timeout,
                )

        tls_info = {"domain": domain, "status": "skipped", "has_tls": False}
        if not no_tls:
            with maybe_spinner(f"Inspecting TLS certificate for {domain}...", no_spinner):
                tls_info = get_ssl_certificate_info(domain, timeout=timeout)

        redirect_info = {"domain": domain, "status": "skipped"}
        if check_redirect:
            with maybe_spinner(f"Checking redirects for {domain}...", no_spinner):
                redirect_info = check_domain_redirect(domain, timeout=timeout)

        formatter = get_formatter(output_format)
        rendered = formatter.format_complete_domain_info(
            registration,
            dns_info,
            ip_info,
            redirect_info if check_redirect else None,
            tls_info,
            input_info=normalized,
            meta=meta,
            email_info=email_info,
        )
        output_result(rendered, output)
    except Exception as exc:
        logger.exception("Error processing %s", domain)
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def configure_logging(verbose: int) -> None:
    if verbose >= 2:
        logging.getLogger("whodis").setLevel(logging.DEBUG)
    elif verbose == 1:
        logging.getLogger("whodis").setLevel(logging.INFO)
    else:
        logging.getLogger("whodis").setLevel(logging.WARNING)


def maybe_spinner(message: str, disabled: bool):
    if disabled:
        return nullcontext()
    return spinning_cursor(message)


if __name__ == "__main__":
    main()
