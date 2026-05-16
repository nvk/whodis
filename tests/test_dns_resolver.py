import unittest

from whois_tool.dns_resolver import DNS_RECORD_TYPES, format_dns_answer


class DnsResolverTests(unittest.TestCase):
    def test_expected_record_types_are_included(self):
        for record_type in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA", "DS", "DNSKEY"]:
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


if __name__ == "__main__":
    unittest.main()
