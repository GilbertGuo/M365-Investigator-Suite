import json
import tempfile
import unittest
from pathlib import Path

from ual_app.store import CaseStore


class StoreCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case_id = "abcdef123456"
        case_dir = self.root / self.case_id
        case_dir.mkdir()
        (case_dir / "meta.json").write_text(json.dumps({"id": self.case_id, "name": "Cache test"}), encoding="utf-8")
        (case_dir / "rows.jsonl").write_text(
            json.dumps({"_Row": 1, "Operation": "UserLoggedIn", "ClientIP": "8.8.8.8"}) + "\n",
            encoding="utf-8",
        )
        self.store = CaseStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_rows_and_overview_are_reused_for_active_case(self):
        rows = self.store.rows(self.case_id)
        self.assertIs(rows, self.store.rows(self.case_id))
        overview = self.store.overview(self.case_id)
        self.assertIs(overview, self.store.overview(self.case_id))

    def test_case_write_invalidates_prepared_rows_and_overview(self):
        rows = self.store.rows(self.case_id)
        overview = self.store.overview(self.case_id)
        self.store.save_enrichment_column(self.case_id, "ClientIP")
        self.assertIsNot(rows, self.store.rows(self.case_id))
        self.assertIsNot(overview, self.store.overview(self.case_id))

    def test_event_column_is_enabled_persistently_for_the_case(self):
        self.assertNotIn("Event", self.store.overview(self.case_id)["columns"])
        self.store.enable_events(self.case_id, [1])
        rows = self.store.rows(self.case_id)
        self.assertIn("UserLoggedIn", rows[0]["Event"])
        self.assertIn("Event", self.store.overview(self.case_id)["columns"])
        self.assertTrue((self.root / self.case_id / "event-summary.json").is_file())

    def test_event_generation_accumulates_only_selected_rows(self):
        case_dir = self.root / self.case_id
        with (case_dir / "rows.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"_Row": 2, "Operation": "FileAccessed", "UserId": "user@example.com"}) + "\n")
        self.store.invalidate(self.case_id)
        self.store.enable_events(self.case_id, [1])
        rows = self.store.rows(self.case_id)
        self.assertIn("Event", rows[0])
        self.assertNotIn("Event", rows[1])
        self.store.enable_events(self.case_id, [2])
        self.assertTrue(all("Event" in row for row in self.store.rows(self.case_id)))


if __name__ == "__main__":
    unittest.main()
