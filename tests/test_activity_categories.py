import unittest

from ual_app.core import ACTIVITY_CATEGORIES, matches_event_category, summarize


class ActivityCategoryTests(unittest.TestCase):
    def test_operation_groups_match_the_review_categories(self):
        expected = {
            "logon": ["UserLoggedIn", "UserLoginFailed"],
            "inbox_rules": ["New-InboxRule", "Set-InboxRule", "UpdateInboxRule", "UpdateInboxRules"],
            "transport_rules": ["New-TransportRule", "Set-TransportRule", "Enable-TransportRule", "Remove-TransportRule"],
            "mailbox_permissions": ["Add-MailboxPermission", "Remove-MailboxPermission"],
            "email_access": ["MailItemsAccessed", "SoftDelete", "Create", "Update", "Move", "MoveToDeletedItems", "HardDelete", "Send", "SendAs"],
            "file_access": [
                "FileAccessed", "FileAccessedExtended", "FilePreviewed", "FileCopied", "FileDeleted",
                "FileDownloaded", "FileModified", "FileModifiedExtended", "SearchQueryPerformed",
                "FolderCopied", "FolderCreated", "FolderMoved", "FolderRename", "FolderRestored",
                "FolderModified", "FolderDeletedFirstStageRecycleBin", "FolderDeletedSecondStageRecycleBin",
            ],
        }
        for category, operations in expected.items():
            for operation in operations:
                with self.subTest(category=category, operation=operation):
                    row = {"Operation": operation}
                    self.assertTrue(matches_event_category(row, category))
                    self.assertFalse(matches_event_category(row, "other"))

    def test_other_contains_uncategorized_operations(self):
        for operation in ("MemberAdded", "Enable-InboxRule", "FileUploaded", ""):
            with self.subTest(operation=operation):
                row = {"Operation": operation}
                self.assertTrue(matches_event_category(row, "other"))
                self.assertFalse(any(matches_event_category(row, category) for category in ACTIVITY_CATEGORIES if category != "other"))

    def test_category_counts_are_mutually_exclusive_and_complete(self):
        rows = [
            {"Operation": "UserloggedIn"},
            {"Operation": "UpdateInboxRules"},
            {"Operation": "Add-MailboxPermission"},
            {"Operation": "MailItemsAccessed"},
            {"Operation": "FileAccessedExtended"},
            {"Operation": "MemberAdded"},
        ]
        categories = summarize(rows)["categories"]
        self.assertEqual(set(categories), set(ACTIVITY_CATEGORIES))
        self.assertEqual(sum(categories.values()), len(rows))
        self.assertEqual(categories["other"], 1)


if __name__ == "__main__":
    unittest.main()
