import json
import tempfile
import unittest
from pathlib import Path

from ual_app.store import CaseStore


class RowTagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case_id = "abcdef123456"
        case_dir = self.root / self.case_id
        case_dir.mkdir()
        (case_dir / "meta.json").write_text(
            json.dumps({"id": self.case_id, "name": "Tag test", "sourceFile": "evidence.csv"}),
            encoding="utf-8",
        )
        rows = [
            {"_Row": 1, "CreationTime": "2026-07-21T10:00:00Z", "Operation": "UserLoggedIn"},
            {"_Row": 2, "CreationTime": "2026-07-21T11:00:00Z", "Operation": "MailItemsAccessed"},
        ]
        (case_dir / "rows.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        self.store = CaseStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_tag_is_added_to_cached_row_and_persists(self):
        rows = self.store.rows(self.case_id)
        overview = self.store.overview(self.case_id)

        result = self.store.set_row_tag(self.case_id, 2, True)

        self.assertEqual(result, {"row": "2", "tagged": True, "taggedCount": 1})
        self.assertEqual(rows[1]["Review.Tag"], "Of interest")
        self.assertIs(rows, self.store.rows(self.case_id))
        self.assertIn("Review.Tag", overview["columns"])
        self.assertEqual(overview["summary"]["tagged"], 1)

        reopened = CaseStore(self.root)
        self.assertEqual(reopened.rows(self.case_id)[1]["Review.Tag"], "Of interest")
        self.assertEqual(reopened.overview(self.case_id)["summary"]["tagged"], 1)

    def test_removing_last_tag_removes_virtual_column(self):
        self.store.rows(self.case_id)
        overview = self.store.overview(self.case_id)
        self.store.set_row_tag(self.case_id, 1, True)

        result = self.store.set_row_tag(self.case_id, 1, False)

        self.assertEqual(result["taggedCount"], 0)
        self.assertNotIn("Review.Tag", self.store.rows(self.case_id)[0])
        self.assertNotIn("Review.Tag", overview["columns"])
        self.assertEqual(json.loads((self.root / self.case_id / "row-tags.json").read_text())["rows"], [])

    def test_invalid_source_row_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid source row"):
            self.store.set_row_tag(self.case_id, "not-a-row", True)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.store.set_row_tag(self.case_id, 999, True)

    def test_bulk_tag_marks_all_matching_rows_once(self):
        rows = self.store.rows(self.case_id)
        overview = self.store.overview(self.case_id)

        first = self.store.set_row_tags(self.case_id, [1, 2], True)
        second = self.store.set_row_tags(self.case_id, [1, 2], True)

        self.assertEqual(first, {"matched": 2, "changed": 2, "tagged": True, "taggedCount": 2})
        self.assertEqual(second["changed"], 0)
        self.assertTrue(all(row["Review.Tag"] == "Of interest" for row in rows))
        self.assertEqual(overview["summary"]["tagged"], 2)
        self.assertEqual(json.loads((self.root / self.case_id / "row-tags.json").read_text())["rows"], ["1", "2"])

        removed = self.store.set_row_tags(self.case_id, [1, 2], False)
        self.assertEqual(removed, {"matched": 2, "changed": 2, "tagged": False, "taggedCount": 0})
        self.assertTrue(all("Review.Tag" not in row for row in rows))


if __name__ == "__main__":
    unittest.main()
