import csv
import io
import json
import unittest

from ual_app.client_xlsx import clean_csv
from ual_app.core import parse_message_trace_rows, read_upload


class LargeCsvFieldTests(unittest.TestCase):
    def csv_bytes(self, headers, values, encoding="utf-8"):
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(headers)
        writer.writerow(values)
        return buffer.getvalue().encode(encoding)

    def test_large_quoted_audit_data_is_preserved(self):
        audit = json.dumps({"Operation": "MailItemsAccessed", "Details": 'value,"quoted"\n' * 20000})
        raw = self.csv_bytes(["Operation", "AuditData"], ["MailItemsAccessed", audit])
        rows = read_upload("audit.csv", raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["AuditData"]), json.loads(audit))

    def test_large_utf16_message_trace_field_is_preserved(self):
        subject = 'Document, "review" — 確認\n' * 10000
        raw = self.csv_bytes(["sender_address", "message_subject"], ["sender@example.com", subject], "utf-16")
        rows = parse_message_trace_rows(read_upload("trace.csv", raw))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Subject"], subject)

    def test_client_csv_reader_accepts_large_fields(self):
        value = "Large field " * 20000
        headers, rows = clean_csv(self.csv_bytes(["Details"], [value]))
        self.assertEqual(headers, ["Details"])
        self.assertEqual(rows, [[value]])
