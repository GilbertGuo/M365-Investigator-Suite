import unittest

from ual_app.core import summarize_metrics


class MetricTests(unittest.TestCase):
    def test_user_count_uses_one_canonical_identity_per_row(self):
        rows = [
            {"UserId": "analyst@example.com", "UserKey": "directory-object-1"},
            {"UserId": "ANALYST@EXAMPLE.COM", "UserKey": "directory-object-1"},
        ]

        self.assertEqual(summarize_metrics(rows)["users"], 1)

    def test_user_count_falls_back_when_user_id_is_missing(self):
        rows = [
            {"UserKey": "directory-object-1"},
            {"MailboxOwnerUPN": "owner@example.com"},
        ]

        self.assertEqual(summarize_metrics(rows)["users"], 2)


if __name__ == "__main__":
    unittest.main()
