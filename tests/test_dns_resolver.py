import unittest
from unittest.mock import patch

from whois_tool.dns_resolver import DNS_RECORD_TYPES, format_dig_answer, format_dns_answer, get_all_dns_info


class DnsResolverTests(unittest.TestCase):
    def test_expected_record_types_are_included(self):
        for record_type in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "SRV", "CAA", "DS", "DNSKEY"]:
            self.assertIn(record_type, DNS_RECORD_TYPES)

    def test_format_mx_answer(self):
        answer = type("MX", (), {"preference": 10, "exchange": "mail.example.com."})()

        self.assertEqual(
            format_dns_answer(answer, "MX"),
            {"preference": 10, "exchange": "mail.example.com"},
        )

    def test_format_null_mx_answer(self):
        answer = type("MX", (), {"preference": 0, "exchange": "."})()

        self.assertEqual(format_dns_answer(answer, "MX"), {"preference": 0, "exchange": "."})

    def test_format_txt_answer(self):
        answer = type("TXT", (), {"strings": [b"v=spf1 ", b"-all"]})()

        self.assertEqual(format_dns_answer(answer, "TXT"), "v=spf1 -all")

    def test_format_caa_answer(self):
        answer = type("CAA", (), {"flags": 0, "tag": b"issue", "value": b"letsencrypt.org"})()

        self.assertEqual(
            format_dns_answer(answer, "CAA"),
            {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
        )

    def test_format_srv_answer(self):
        answer = type(
            "SRV",
            (),
            {"priority": 10, "weight": 5, "port": 443, "target": "service.example.com."},
        )()

        self.assertEqual(
            format_dns_answer(answer, "SRV"),
            {"priority": 10, "weight": 5, "port": 443, "target": "service.example.com"},
        )

    def test_format_dig_mx_answer(self):
        self.assertEqual(
            format_dig_answer("10 mail.example.com.", "MX"),
            {"preference": 10, "exchange": "mail.example.com"},
        )

    def test_format_dig_null_mx_answer(self):
        self.assertEqual(format_dig_answer("0 .", "MX"), {"preference": 0, "exchange": "."})

    def test_get_all_dns_info_includes_ptr_records(self):
        def fake_resolve(domain, record_type, timeout=10):
            if record_type == "A":
                return {"status": "ok", "records": ["1.1.1.1"]}
            return {"status": "no_answer", "records": []}

        with patch("whois_tool.dns_resolver.resolve_dns_python", side_effect=fake_resolve), patch(
            "whois_tool.dns_resolver.get_ptr_records", return_value={"1.1.1.1": ["one.one.one.one"]}
        ):
            result = get_all_dns_info("example.com")

        self.assertEqual(result["records"]["PTR"], {"1.1.1.1": ["one.one.one.one"]})


if __name__ == "__main__":
    unittest.main()
