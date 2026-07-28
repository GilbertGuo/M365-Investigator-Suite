import unittest

from ual_app.server import column_value_facets


class ColumnValueFacetTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"Login.OS": "Windows", "UserId": "a@example.com"},
            {"Login.OS": "Windows", "UserId": "b@example.com"},
            {"Login.OS": "macOS", "UserId": "c@example.com"},
            {"UserId": "d@example.com"},
            {"Login.OS": "", "UserId": "e@example.com"},
        ]

    def test_counts_distinct_values_and_missing_as_empty(self):
        result = column_value_facets(self.rows, "Login.OS")
        self.assertEqual(result["totalUnique"], 3)
        self.assertEqual(result["values"][0], {"value": "", "label": "(empty)", "count": 2})
        self.assertEqual(result["values"][1]["value"], "Windows")
        self.assertEqual(result["values"][1]["count"], 2)

    def test_search_and_pagination(self):
        result = column_value_facets(self.rows, "Login.OS", search="win", limit=1)
        self.assertEqual(result["matchingUnique"], 1)
        self.assertFalse(result["hasMore"])
        self.assertEqual(result["values"][0]["value"], "Windows")


if __name__ == "__main__":
    unittest.main()
