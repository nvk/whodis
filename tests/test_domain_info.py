import unittest

from whois_tool.rdap import build_rdap_url, find_matching_rdap_services, summarize_rdap_domain
from whois_tool.utils import normalize_domain_input


class DomainRdapTests(unittest.TestCase):
    def test_normalize_url_input(self):
        result = normalize_domain_input("https://WWW.Example.COM:443/path?q=1")

        self.assertTrue(result["valid"])
        self.assertEqual(result["domain"], "www.example.com")
        self.assertEqual(result["display_domain"], "www.example.com")

    def test_normalize_scheme_less_url_with_path(self):
        result = normalize_domain_input("example.com/path")

        self.assertTrue(result["valid"])
        self.assertEqual(result["domain"], "example.com")

    def test_normalize_email_like_input(self):
        result = normalize_domain_input("admin@exämple.com")

        self.assertTrue(result["valid"])
        self.assertEqual(result["domain"], "xn--exmple-cua.com")
        self.assertEqual(result["display_domain"], "exämple.com")

    def test_rdap_bootstrap_uses_longest_label_match(self):
        bootstrap = {
            "services": [
                [["com"], ["https://rdap.example/com/"]],
                [["example.com"], ["https://rdap.example/example/"]],
            ]
        }

        self.assertEqual(
            find_matching_rdap_services("www.example.com", bootstrap),
            ["https://rdap.example/example/"],
        )

    def test_build_rdap_domain_url(self):
        self.assertEqual(
            build_rdap_url("https://rdap.example/base", "domain", "example.com"),
            "https://rdap.example/base/domain/example.com",
        )

    def test_summarize_rdap_domain(self):
        summary = summarize_rdap_domain(
            {
                "objectClassName": "domain",
                "ldhName": "EXAMPLE.COM",
                "handle": "123",
                "status": ["client transfer prohibited"],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "handle": "REG",
                        "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                        "entities": [
                            {
                                "roles": ["abuse"],
                                "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.test"]]],
                            }
                        ],
                    }
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
                ],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "secureDNS": {"delegationSigned": True},
            }
        )

        self.assertEqual(summary["domain"], "EXAMPLE.COM")
        self.assertEqual(summary["registrar"]["name"], "Example Registrar")
        self.assertEqual(summary["registrar"]["iana_id"], "376")
        self.assertEqual(summary["abuse_contact"]["email"], "abuse@example.test")
        self.assertEqual(summary["created"], "1995-08-14T04:00:00Z")
        self.assertEqual(summary["expires"], "2026-08-13T04:00:00Z")
        self.assertEqual(summary["nameservers"], ["NS1.EXAMPLE.COM"])


if __name__ == "__main__":
    unittest.main()
