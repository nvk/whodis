import unittest
from unittest.mock import patch

from whois_tool.ip_info import detect_hosting_provider, get_ip_info_for_domain


class IpInfoTests(unittest.TestCase):
    def test_detect_known_provider_by_asn(self):
        self.assertEqual(detect_hosting_provider("", "", "13335"), "Cloudflare")

    def test_detect_known_provider_by_name(self):
        self.assertEqual(detect_hosting_provider("GOOGLE-CLOUD", "", ""), "Google Cloud")

    def test_get_ip_info_for_domain_deduplicates_addresses(self):
        with patch("whois_tool.ip_info.get_ip_info", return_value={"status": "ok", "ip": "1.1.1.1"}):
            result = get_ip_info_for_domain("example.com", ["1.1.1.1", "1.1.1.1"])

        self.assertEqual(result["status"], "ok")
        self.assertEqual(list(result["addresses"].keys()), ["1.1.1.1"])


if __name__ == "__main__":
    unittest.main()
