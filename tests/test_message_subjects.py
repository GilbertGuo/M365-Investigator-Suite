import json
import tempfile
import unittest
from pathlib import Path

from ual_app.core import extract_message_subject_details, extract_message_subject_pairs, message_subject_export_rows, normalize_message_id_display
from ual_app.store import CaseStore


class MessageSubjectTests(unittest.TestCase):
    def test_pairs_nested_folder_items_without_cross_matching(self):
        row = {
            "Folders": json.dumps([{"FolderItems": [
                {"InternetMessageId": "<first@example.com>", "Subject": "First subject"},
                {"InternetMessageId": "<second@example.com>", "Subject": "Second subject", "SizeInBytes": 2048},
            ]}]),
            "InternetMessageIDs": "first@example.com; second@example.com",
        }
        self.assertEqual(extract_message_subject_pairs(row), [
            ("<first@example.com>", "First subject"),
            ("<second@example.com>", "Second subject"),
        ])
        self.assertEqual(extract_message_subject_details(row), [
            ("<first@example.com>", "First subject", ""),
            ("<second@example.com>", "Second subject", "2048"),
        ])

    def test_pairs_flattened_item_fields(self):
        row = {"Item.InternetMessageId": "<flat@example.com>", "Item.Subject": "Flat subject", "Item.SizeInBytes": 4096}
        self.assertEqual(extract_message_subject_pairs(row), [("<flat@example.com>", "Flat subject")])
        self.assertEqual(extract_message_subject_details(row), [("<flat@example.com>", "Flat subject", "4096")])

    def test_pairs_item_and_item1_python_literal_columns(self):
        row = {
            "Operation": "Send",
            "Item": "{'Subject': 'Primary subject', 'InternetMessageId': '<primary@example.com>'}",
            "Item.1": "{'Subject': 'Secondary subject', 'InternetMessageId': '<secondary@example.com>'}",
        }
        self.assertEqual(extract_message_subject_pairs(row), [
            ("<primary@example.com>", "Primary subject"),
            ("<secondary@example.com>", "Secondary subject"),
        ])

    def test_pairs_python_literal_payloads_for_non_access_operations(self):
        item_operations = ("Send", "Create", "Update")
        affected_operations = ("MoveToDeletedItems", "SoftDelete", "HardDelete")
        for operation in item_operations:
            with self.subTest(operation=operation):
                row = {
                    "Operation": operation,
                    "Item": "{'Subject': 'Item subject', 'InternetMessageId': '<item@example.com>'}",
                }
                self.assertEqual(extract_message_subject_pairs(row), [("<item@example.com>", "Item subject")])
        for operation in affected_operations:
            with self.subTest(operation=operation):
                row = {
                    "Operation": operation,
                    "AffectedItems": "[{'Subject': 'Affected subject', 'InternetMessageId': '<affected@example.com>'}]",
                }
                self.assertEqual(extract_message_subject_pairs(row), [("<affected@example.com>", "Affected subject")])

    def test_supports_single_quoted_regex_shape_and_missing_subject(self):
        row = {
            "Raw": "{'InternetMessageId': '<regex@example.com>', 'Subject': 'Regex subject'}",
            "InternetMessageIDs": "regex@example.com; missing@example.com",
        }
        self.assertEqual(extract_message_subject_pairs(row), [
            ("<regex@example.com>", "Regex subject"),
            ("<missing@example.com>", ""),
        ])

    def test_existing_case_message_ids_are_normalized_with_angle_brackets(self):
        row = {"InternetMessageIDs": "first@example.com; <second@example.com>", "Item.InternetMessageId": "third@example.com"}
        self.assertEqual(normalize_message_id_display(row), {
            "InternetMessageIDs": "<first@example.com>; <second@example.com>",
            "Item.InternetMessageId": "<third@example.com>",
        })

    def test_export_rows_deduplicate_ids_and_keep_the_best_subject(self):
        rows = [
            {"MessageSubject.Pairs": "<first@example.com> → (no subject)\n<second@example.com> → Second subject", "MessageSubject.SizeInBytes": "(not recorded); 2048"},
            {"MessageSubject.Pairs": "first@example.com → First subject\n<SECOND@example.com> → Duplicate subject", "MessageSubject.SizeInBytes": "1024; (not recorded)"},
        ]
        self.assertEqual(message_subject_export_rows(rows), [
            {"InternetMessageId": "<first@example.com>", "Subject": "First subject"},
            {"InternetMessageId": "<second@example.com>", "Subject": "Second subject"},
        ])
        self.assertEqual(message_subject_export_rows(rows, include_size=True), [
            {"InternetMessageId": "<first@example.com>", "Subject": "First subject", "SizeInBytes": "1024"},
            {"InternetMessageId": "<second@example.com>", "Subject": "Second subject", "SizeInBytes": "2048"},
        ])

    def test_store_export_uses_only_the_supplied_filtered_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_id = "abcdef123456"
            case_dir = root / case_id
            case_dir.mkdir()
            (case_dir / "meta.json").write_text(json.dumps({"id": case_id, "name": "Synthetic"}), encoding="utf-8")
            source_rows = [
                {"_Row": 1, "Raw": "{'InternetMessageId': '<first@example.com>', 'Subject': 'First subject'}"},
                {"_Row": 2, "Raw": "{'InternetMessageId': '<second@example.com>', 'Subject': 'Second subject', 'SizeInBytes': 8192}"},
            ]
            (case_dir / "rows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in source_rows), encoding="utf-8")
            store = CaseStore(root)
            (case_dir / "message-subject-analysis.json").write_text(json.dumps({"findings": {}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "before exporting SizeInBytes"):
                store.exported_message_subject_pairs(case_id, [], include_size=True)
            store.extract_message_subjects(case_id)
            filtered_rows = [row for row in store.rows(case_id) if row["_Row"] == 2]
            self.assertEqual(filtered_rows[0]["MessageSubject.SizeInBytes"], "8192")
            self.assertEqual(store.exported_message_subject_pairs(case_id, filtered_rows, include_size=True), [
                {"InternetMessageId": "<second@example.com>", "Subject": "Second subject", "SizeInBytes": "8192"},
            ])


if __name__ == "__main__":
    unittest.main()
