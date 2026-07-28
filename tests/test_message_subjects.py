import json
import unittest

from ual_app.core import extract_message_subject_pairs, normalize_message_id_display


class MessageSubjectTests(unittest.TestCase):
    def test_pairs_nested_folder_items_without_cross_matching(self):
        row = {
            "Folders": json.dumps([{"FolderItems": [
                {"InternetMessageId": "<first@example.com>", "Subject": "First subject"},
                {"InternetMessageId": "<second@example.com>", "Subject": "Second subject"},
            ]}]),
            "InternetMessageIDs": "first@example.com; second@example.com",
        }
        self.assertEqual(extract_message_subject_pairs(row), [
            ("<first@example.com>", "First subject"),
            ("<second@example.com>", "Second subject"),
        ])

    def test_pairs_flattened_item_fields(self):
        row = {"Item.InternetMessageId": "<flat@example.com>", "Item.Subject": "Flat subject"}
        self.assertEqual(extract_message_subject_pairs(row), [("<flat@example.com>", "Flat subject")])

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


if __name__ == "__main__":
    unittest.main()
