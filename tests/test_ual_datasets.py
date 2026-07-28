import json
import tempfile
import unittest
from pathlib import Path

from ual_app.store import CaseStore


class UalDatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = CaseStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_empty_case_accepts_multiple_independent_ual_datasets(self):
        case = self.store.create_case("BEC investigation")
        self.assertEqual(self.store.ual_datasets(case["id"]), [])
        first = self.store.create_ual_dataset(
            case["id"], "first.csv",
            b"CreationTime,Operation,UserId\n2026-07-01T10:00:00Z,UserLoggedIn,first@example.com\n",
            "Initial export",
        )
        second = self.store.create_ual_dataset(
            case["id"], "second.csv",
            b"CreationTime,Operation,UserId\n2026-07-02T10:00:00Z,FileAccessed,second@example.com\n",
            "Follow-up export",
        )
        datasets = self.store.ual_datasets(case["id"])
        self.assertEqual({item["name"] for item in datasets}, {"Initial export", "Follow-up export"})
        self.assertEqual(self.store.rows(first["id"])[0]["UserId"], "first@example.com")
        self.assertEqual(self.store.rows(second["id"])[0]["UserId"], "second@example.com")
        self.store.set_row_tags(first["id"], [1], True)
        self.assertEqual(self.store.rows(first["id"])[0]["Review.Tag"], "Of interest")
        self.assertNotIn("Review.Tag", self.store.rows(second["id"])[0])
        listed_case = next(item for item in self.store.list() if item["id"] == case["id"])
        self.assertEqual(listed_case["ualDatasetCount"], 2)
        self.assertEqual(listed_case["rowCount"], 2)
        self.store.delete_ual_dataset(case["id"], first["id"])
        self.assertEqual([item["id"] for item in self.store.ual_datasets(case["id"])], [second["id"]])

    def test_existing_case_is_exposed_as_legacy_ual_dataset(self):
        case_id = "abcdef123456"
        case_dir = self.root / case_id
        case_dir.mkdir()
        (case_dir / "meta.json").write_text(json.dumps({"id": case_id, "name": "Legacy", "sourceFile": "old.csv", "createdAt": "2026-01-01T00:00:00Z", "rowCount": 99}), encoding="utf-8")
        (case_dir / "rows.jsonl").write_text(json.dumps({"_Row": 1, "Operation": "UserLoggedIn"}) + "\n", encoding="utf-8")
        datasets = self.store.ual_datasets(case_id)
        self.assertEqual(len(datasets), 1)
        self.assertEqual(datasets[0]["id"], case_id)
        self.assertEqual(datasets[0]["rowCount"], 1)
        self.assertTrue(datasets[0]["legacy"])


if __name__ == "__main__":
    unittest.main()
