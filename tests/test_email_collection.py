import base64
import json
import tempfile
import unittest
from pathlib import Path

from ual_app.email_collection import collect_emails, csv_targets, manual_targets


class FakeResponse:
    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class EmailCollectionTests(unittest.TestCase):
    def test_manual_targets_normalize_and_deduplicate_ids(self):
        targets = manual_targets("analyst@example.test", "first@example.test\n<second@example.test>\nfirst@example.test")
        self.assertEqual(2, len(targets))
        self.assertEqual("<first@example.test>", targets[0]["InternetMessageId"])
        self.assertEqual("<second@example.test>", targets[1]["InternetMessageId"])

    def test_csv_targets_accepts_required_headers_and_utf16(self):
        raw = "MailboxOwnerUPN,InternetMessageId\r\nanalyst@example.test,id@example.test\r\n".encode("utf-16")
        self.assertEqual([{
            "MailboxOwnerUPN": "analyst@example.test",
            "InternetMessageId": "<id@example.test>",
        }], csv_targets(raw))

    def test_csv_targets_rejects_missing_columns(self):
        with self.assertRaisesRegex(ValueError, "MailboxOwnerUPN and InternetMessageId"):
            csv_targets(b"Mailbox,MessageId\nanalyst@example.test,id@example.test\n")

    def test_collects_eml_attachment_and_report_without_secret(self):
        calls = []

        def opener(request, timeout=60):
            calls.append(request.full_url)
            if "oauth2/v2.0/token" in request.full_url:
                self.assertIn(b"client_secret=top-secret", request.data)
                return FakeResponse({"access_token": "token"})
            if request.full_url.endswith("/$value"):
                return FakeResponse(b"From: sender@example.test\r\n\r\nEvidence")
            if "/attachments?" in request.full_url:
                return FakeResponse({"value": [{
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "invoice.txt",
                    "contentBytes": base64.b64encode(b"attachment").decode(),
                }]})
            if "/messages?" in request.full_url:
                return FakeResponse({"value": [{
                    "id": "graph-id", "subject": "Test subject",
                    "internetMessageId": "<id@example.test>", "hasAttachments": True,
                }]})
            self.fail(f"Unexpected request: {request.full_url}")

        with tempfile.TemporaryDirectory() as folder:
            result = collect_emails(
                "tenant", "client", "top-secret", folder,
                [{"MailboxOwnerUPN": "analyst@example.test", "InternetMessageId": "id@example.test"}],
                opener=opener,
            )
            self.assertEqual(1, result["collected"])
            self.assertTrue(Path(result["reportPath"]).exists())
            self.assertEqual(b"attachment", next(Path(folder).rglob("invoice.txt")).read_bytes())
            self.assertIn(b"Evidence", next(Path(folder).rglob("Test subject.eml")).read_bytes())
            self.assertNotIn("top-secret", Path(result["reportPath"]).read_text(encoding="utf-8-sig"))
            self.assertTrue(any("internetMessageId" in url for url in calls))


if __name__ == "__main__":
    unittest.main()
