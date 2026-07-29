import unittest

from ual_app.core import analyze_impossible_travel
from ual_app.server import sort_review_rows


class ImpossibleTravelTests(unittest.TestCase):
    def test_finding_includes_previous_and_current_isp(self):
        rows = [
            {"_Row": 1, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T10:00:00",
             "UserId": "user@example.com", "ClientIP": "198.51.100.1"},
            {"_Row": 2, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T11:00:00",
             "UserId": "user@example.com", "ClientIP": "203.0.113.2"},
        ]
        enrichment = {
            "198.51.100.1": {"Lookup_Status": "Success", "Country": "United States", "Region": "New York", "ISP": "Previous ISP"},
            "203.0.113.2": {"Lookup_Status": "Success", "Country": "Canada", "Region": "Ontario", "ISP": "Current ISP"},
        }
        finding = analyze_impossible_travel(rows, enrichment, ["ClientIP"])["2"]
        self.assertEqual(finding["PreviousISP"], "Previous ISP")
        self.assertEqual(finding["CurrentISP"], "Current ISP")

    def test_country_change_window_is_configurable(self):
        rows = [
            {"_Row": 1, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T10:00:00",
             "UserId": "user@example.com", "ClientIP": "198.51.100.1"},
            {"_Row": 2, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T11:00:00",
             "UserId": "user@example.com", "ClientIP": "203.0.113.2"},
        ]
        enrichment = {
            "198.51.100.1": {"Lookup_Status": "Success", "Country": "United States", "Region": "New York"},
            "203.0.113.2": {"Lookup_Status": "Success", "Country": "Canada", "Region": "Ontario"},
        }
        settings = {"useCountryChange": True, "countryHours": 0.5, "useRegionChange": False,
                    "useElevatedWindow": False}
        self.assertEqual(analyze_impossible_travel(rows, enrichment, ["ClientIP"], settings), {})

    def test_elevated_window_signals_are_selectable(self):
        rows = [
            {"_Row": 1, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T10:00:00",
             "UserId": "user@example.com", "ClientIP": "198.51.100.1"},
            {"_Row": 2, "Operation": "UserLoggedIn", "CreationTime": "2026-01-01T20:00:00",
             "UserId": "user@example.com", "ClientIP": "203.0.113.2"},
        ]
        enrichment = {
            "198.51.100.1": {"Lookup_Status": "Success", "Country": "United States", "Region": "New York"},
            "203.0.113.2": {"Lookup_Status": "Success", "Country": "Canada", "Region": "Ontario", "Hosting": True},
        }
        enabled = {"useCountryChange": False, "useRegionChange": False, "useElevatedWindow": True,
                   "elevatedHours": 12, "useHosting": True, "useProxy": False, "useDeviceRisk": False}
        disabled = dict(enabled, useHosting=False, useProxy=True)
        self.assertIn("2", analyze_impossible_travel(rows, enrichment, ["ClientIP"], enabled))
        self.assertEqual(analyze_impossible_travel(rows, enrichment, ["ClientIP"], disabled), {})

    def test_travel_risk_and_score_sorting(self):
        rows = [
            {"Travel.Risk": "High", "Travel.Score": 10},
            {"Travel.Risk": "Low", "Travel.Score": 2},
            {"Travel.Risk": "Medium", "Travel.Score": 6},
            {"Travel.Risk": "", "Travel.Score": ""},
        ]
        self.assertEqual([row["Travel.Risk"] for row in sort_review_rows(rows[:], "Travel.Risk", "asc")], ["Low", "Medium", "High", ""])
        self.assertEqual([row["Travel.Risk"] for row in sort_review_rows(rows[:], "Travel.Risk", "desc")], ["High", "Medium", "Low", ""])
        self.assertEqual([row["Travel.Score"] for row in sort_review_rows(rows[:], "Travel.Score", "asc")], [2, 6, 10, ""])
        self.assertEqual([row["Travel.Score"] for row in sort_review_rows(rows[:], "Travel.Score", "desc")], [10, 6, 2, ""])

    def test_any_timestamp_named_column_sorts_chronologically(self):
        field = "SenderAddress_WHOIS_RegistrationDate"
        rows = [
            {field: "2026-01-01T06:00:00-05:00"},
            {field: "2026-01-01T10:00:00Z"},
            {field: "2025-12-31T23:00:00Z"},
            {field: "unknown"},
            {field: ""},
        ]
        ascending = [row[field] for row in sort_review_rows(rows[:], field, "asc")]
        self.assertEqual(ascending[:3], ["2025-12-31T23:00:00Z", "2026-01-01T10:00:00Z", "2026-01-01T06:00:00-05:00"])
        self.assertEqual(ascending[-2:], ["unknown", ""])
        descending = [row[field] for row in sort_review_rows(rows[:], field, "desc")]
        self.assertEqual(descending[:3], ["2026-01-01T06:00:00-05:00", "2026-01-01T10:00:00Z", "2025-12-31T23:00:00Z"])
        self.assertEqual(descending[-2:], ["unknown", ""])


if __name__ == "__main__":
    unittest.main()
