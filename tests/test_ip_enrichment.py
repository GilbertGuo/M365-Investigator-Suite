import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from ual_app.core import enrich_ips_ipapi
from ual_app.server import ip_api_credentials


class IpEnrichmentTests(unittest.TestCase):
    def test_commercial_key_uses_https_pro_batch_without_persisting_key(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'[{"status":"success","query":"8.8.8.8","country":"United States"}]'
        response.headers = {}
        with patch("ual_app.core.urllib.request.urlopen", return_value=response) as lookup:
            results = enrich_ips_ipapi(["8.8.8.8"], api_key="commercial-key-123")
        request = lookup.call_args.args[0]
        parsed = urlparse(request.full_url)
        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", "https://pro.ip-api.com/batch")
        self.assertEqual(parse_qs(parsed.query)["key"], ["commercial-key-123"])
        self.assertEqual(results["8.8.8.8"]["Provider"], "ip-api.com Pro")
        self.assertNotIn("commercial-key-123", str(results))

    def test_free_terms_or_commercial_key_are_required(self):
        self.assertEqual(ip_api_credentials({"acceptNonCommercialTerms": True}), "")
        self.assertEqual(ip_api_credentials({"apiKey": "commercial-key-123"}), "commercial-key-123")
        with self.assertRaisesRegex(ValueError, "Accept ip-api.com"):
            ip_api_credentials({})
        with self.assertRaisesRegex(ValueError, "invalid"):
            ip_api_credentials({"apiKey": "bad key"})


if __name__ == "__main__":
    unittest.main()
