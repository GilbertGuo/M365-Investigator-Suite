import unittest

from ual_app.server import csv_download_name


class ExportFilenameTests(unittest.TestCase):
    def test_adds_csv_extension(self):
        self.assertEqual(csv_download_name("Incident review"), "Incident review.csv")

    def test_does_not_duplicate_extension(self):
        self.assertEqual(csv_download_name("evidence.CSV"), "evidence.csv")

    def test_removes_paths_and_header_unsafe_characters(self):
        self.assertEqual(csv_download_name("../../Case\r\nInjected: value.csv"), "Case_Injected_ value.csv")
        self.assertEqual(csv_download_name(r"C:\Cases\Client export.csv"), "Client export.csv")

    def test_uses_safe_fallback_for_empty_name(self):
        self.assertEqual(csv_download_name("...", "abc123-ual-export"), "abc123-ual-export.csv")


if __name__ == "__main__":
    unittest.main()
