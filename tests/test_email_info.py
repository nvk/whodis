import unittest
from unittest.mock import Mock, patch

from whois_tool.email_info import (
    get_dmarc_info,
    get_email_info,
    get_mta_sts_info,
    get_spf_info,
    normalize_mx_records,
    parse_mta_sts_policy,
    parse_spf_record,
)


class EmailInfoTests(unittest.TestCase):
    def test_normalize_mx_records_sorts_and_handles_null_mx(self):
        self.assertEqual(
            normalize_mx_records(
                [
                    {"preference": 20, "exchange": "mail2.example.com."},
                    {"preference": 0, "exchange": "."},
                    "10 mail.example.com.",
                ]
            ),
            [
                {"preference": 0, "exchange": "."},
                {"preference": 10, "exchange": "mail.example.com"},
                {"preference": 20, "exchange": "mail2.example.com"},
            ],
        )

    def test_parse_spf_counts_dns_lookups_and_warns_on_softfail(self):
        result = parse_spf_record("v=spf1 include:_spf.example.com ip4:192.0.2.0/24 ~all")

        self.assertEqual(result["dns_lookup_count"], 1)
        self.assertEqual(result["mechanisms"][0]["mechanism"], "include")
        self.assertIn("SPF ends in ~all; softfail is weaker than -all.", result["warnings"])

    def test_parse_spf_warns_on_plus_all(self):
        result = parse_spf_record("v=spf1 +all")

        self.assertIn("SPF ends in +all, allowing any sender.", result["warnings"])

    def test_get_spf_info_warns_on_multiple_records(self):
        dns_info = {
            "status": "ok",
            "records": {"TXT": ["v=spf1 -all", "v=spf1 include:_spf.example.com -all"]},
            "queries": {"TXT": {"status": "ok", "records": []}},
        }

        result = get_spf_info("example.com", dns_info=dns_info)

        self.assertEqual(result["status"], "multiple")
        self.assertIn("Multiple SPF records found; receivers can treat SPF as permanent error.", result["warnings"])

    def test_get_dmarc_info_parses_policy_tags(self):
        dns_info = {
            "dmarc": {
                "status": "ok",
                "records": [
                    "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
                ],
            }
        }

        result = get_dmarc_info("example.com", dns_info=dns_info)

        self.assertEqual(result["policy"], "quarantine")
        self.assertEqual(result["subdomain_policy"], "reject")
        self.assertEqual(result["alignment"], {"adkim": "s", "aspf": "s"})
        self.assertEqual(result["rua"], ["mailto:dmarc@example.com"])
        self.assertIn("DMARC pct=50; policy is not applied to all mail.", result["warnings"])

    def test_parse_mta_sts_policy_collects_multiple_mx_hosts(self):
        result = parse_mta_sts_policy(
            "\n".join(
                [
                    "version: STSv1",
                    "mode: enforce",
                    "mx: mail.example.com",
                    "mx: *.example.net",
                    "max_age: 86400",
                ]
            )
        )

        self.assertEqual(result["version"], "STSv1")
        self.assertEqual(result["mode"], "enforce")
        self.assertEqual(result["mx"], ["mail.example.com", "*.example.net"])
        self.assertEqual(result["max_age_seconds"], 86400)

    def test_get_mta_sts_info_fetches_policy_when_txt_exists(self):
        response = Mock(status_code=200, text="version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n")

        with patch("whois_tool.email_info.resolve_dns_python") as resolve_dns, patch(
            "whois_tool.email_info.requests.get", return_value=response
        ) as request_get:
            resolve_dns.return_value = {"status": "ok", "records": ["v=STSv1; id=2026051501"]}
            result = get_mta_sts_info("example.com")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["policy"]["mode"], "testing")
        request_get.assert_called_once()

    def test_get_email_info_aggregates_mx_spf_dmarc_and_reporting(self):
        dns_info = {
            "status": "ok",
            "records": {
                "MX": [{"preference": 10, "exchange": "mail.example.com"}],
                "TXT": ["v=spf1 -all"],
            },
            "queries": {"MX": {"status": "ok", "records": []}, "TXT": {"status": "ok", "records": []}},
            "dmarc": {"status": "ok", "records": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
        }

        def fake_resolve(domain, record_type, timeout=10):
            answers = {
                ("mail.example.com", "A"): {"status": "ok", "records": ["192.0.2.10"]},
                ("mail.example.com", "AAAA"): {"status": "no_answer", "records": []},
                ("_mta-sts.example.com", "TXT"): {"status": "no_answer", "records": []},
                ("_smtp._tls.example.com", "TXT"): {
                    "status": "ok",
                    "records": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
                },
                ("default._bimi.example.com", "TXT"): {"status": "no_answer", "records": []},
            }
            return answers.get((domain, record_type), {"status": "no_answer", "records": []})

        with patch("whois_tool.email_info.resolve_dns_python", side_effect=fake_resolve), patch(
            "whois_tool.email_info.get_ptr_records", return_value={"192.0.2.10": ["mail.example.com"]}
        ):
            result = get_email_info("example.com", dns_info=dns_info)

        self.assertEqual(result["mx"]["hosts"][0]["addresses"], ["192.0.2.10"])
        self.assertEqual(result["spf"]["status"], "ok")
        self.assertEqual(result["dmarc"]["policy"], "reject")
        self.assertEqual(result["tls_rpt"]["rua"], ["mailto:tls@example.com"])


if __name__ == "__main__":
    unittest.main()
