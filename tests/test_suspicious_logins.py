import unittest

from ual_app.core import analyze_suspicious_logins


class SuspiciousLoginTests(unittest.TestCase):
    def test_foreign_login_is_flagged_and_includes_isp(self):
        rows = [{
            "_Row": 1, "Operation": "UserLoggedIn", "ClientIP": "203.0.113.10",
            "Login.IsCompliant": True, "Login.IsCompliantAndManaged": True,
        }]
        enrichment = {"203.0.113.10": {
            "Lookup_Status": "Success", "Country": "Canada", "Region": "Ontario", "City": "Toronto",
            "ISP": "Example ISP", "Proxy_VPN_TOR": False, "Hosting": False,
        }}
        finding = analyze_suspicious_logins(rows, enrichment, ["ClientIP"])["1"]
        self.assertEqual(finding["ISP"], "Example ISP")
        self.assertIn("outside trusted countries (Canada)", finding["Reasons"])

    def test_us_login_keeps_infrastructure_and_device_posture_rule(self):
        rows = [
            {"_Row": 1, "Operation": "UserLoginFailed", "ClientIP": "198.51.100.1",
             "Login.IsCompliant": False, "Login.IsCompliantAndManaged": ""},
            {"_Row": 2, "Operation": "UserLoggedIn", "ClientIP": "198.51.100.2",
             "Login.IsCompliant": True, "Login.IsCompliantAndManaged": True},
        ]
        enrichment = {
            "198.51.100.1": {"Lookup_Status": "Success", "Country": "United States", "ISP": "VPN ISP", "Proxy_VPN_TOR": True, "Hosting": False},
            "198.51.100.2": {"Lookup_Status": "Success", "Country": "USA", "ISP": "Normal ISP", "Proxy_VPN_TOR": False, "Hosting": False},
        }
        findings = analyze_suspicious_logins(rows, enrichment, ["ClientIP"])
        self.assertIn("1", findings)
        self.assertNotIn("2", findings)

    def test_trusted_countries_are_configurable(self):
        rows = [{"_Row": 1, "Operation": "UserLoggedIn", "ClientIP": "203.0.113.10",
                 "Login.IsCompliant": True, "Login.IsCompliantAndManaged": True}]
        enrichment = {"203.0.113.10": {"Lookup_Status": "Success", "Country": "Canada",
                                                    "Proxy_VPN_TOR": False, "Hosting": False}}
        settings = {"useCountry": True, "trustedCountries": ["Canada"], "useProxy": False, "useHosting": False}
        self.assertEqual(analyze_suspicious_logins(rows, enrichment, ["ClientIP"], settings), {})

    def test_infrastructure_can_be_used_without_device_posture_requirement(self):
        rows = [{"_Row": 1, "Operation": "UserLoggedIn", "ClientIP": "198.51.100.8",
                 "Login.IsCompliant": True, "Login.IsCompliantAndManaged": True}]
        enrichment = {"198.51.100.8": {"Lookup_Status": "Success", "Country": "United States",
                                                   "Proxy_VPN_TOR": True, "Hosting": False}}
        settings = {"useCountry": False, "useProxy": True, "useHosting": False, "requireDeviceRisk": False}
        findings = analyze_suspicious_logins(rows, enrichment, ["ClientIP"], settings)
        self.assertIn("1", findings)
        self.assertIn("Proxy/VPN/TOR indicator", findings["1"]["Reasons"])


if __name__ == "__main__":
    unittest.main()
