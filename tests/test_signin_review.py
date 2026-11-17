import csv
import hashlib
import io
import tempfile
import time
import unittest
from pathlib import Path

from ual_app.signin_review import COLUMNS, prepare_signin_review
from ual_app.store import CaseStore


class SigninReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, headers, rows):
        source, output = self.root / 'source.csv', self.root / 'result.csv'
        with source.open('w', encoding='utf-8-sig', newline='') as incoming:
            writer = csv.writer(incoming)
            writer.writerow(headers)
            writer.writerows(rows)
        original = source.read_bytes()
        result = prepare_signin_review(source, output)
        self.assertEqual(source.read_bytes(), original)
        with output.open(encoding='utf-8-sig', newline='') as outgoing:
            reader = csv.DictReader(outgoing)
            return result, reader.fieldnames, list(reader)

    def test_matches_script_column_order_and_fallbacks(self):
        headers = ['CreationTime', 'UserId', 'AuditData.UserId', 'ClientIP', 'SuspiciousLogin.IP', 'ActorIpAddress',
                   'SuspiciousLogin.Location', 'GeoLocation', 'SuspiciousLogin.ISP', 'ClientIP_IPAPI_ISP',
                   'ApplicationDisplayName', 'AppMapping.ApplicationId', 'Login.IsCompliant', 'Login.SessionId', 'SessionId', 'RecordId', 'Id']
        result, output_headers, rows = self.prepare(headers, [
            ['2026-01-01T12:00:00Z', ' user@example.com ', 'other@example.com', '203.0.113.10', '203.0.113.11', '',
             'Canada', 'Elsewhere', '', 'Example ISP', '', 'Example app', 'False', '', 'session-example', '', 'record-example'],
            ['', '', 'fallback@example.com', '', '', '203.0.113.12', '', '', '', '', '', '', '', '', '', '', ''],
        ])
        self.assertEqual(output_headers, ['Time (UTC)', 'User', 'IP Address', 'Location', 'ISP', 'Operation', 'Result',
                                         'Result Detail', 'Application', 'Request Type', 'OS', 'Browser', 'Device Compliant',
                                         'Risk (Heuristic)', 'Risk Reasons (Heuristic)', 'Session ID', 'Record ID'])
        self.assertEqual(result['rowCount'], 2)
        self.assertEqual(rows[0]['User'], 'user@example.com')
        self.assertEqual(rows[0]['IP Address'], '203.0.113.10')
        self.assertEqual(rows[0]['Location'], 'Canada')
        self.assertEqual(rows[0]['ISP'], 'Example ISP')
        self.assertEqual(rows[0]['Application'], 'Example app')
        self.assertEqual(rows[0]['Device Compliant'], 'False')
        self.assertEqual(rows[0]['Session ID'], 'session-example')
        self.assertEqual(rows[0]['Record ID'], 'record-example')
        self.assertEqual(rows[1]['User'], 'fallback@example.com')
        self.assertEqual(rows[1]['IP Address'], '203.0.113.12')

    def test_preserves_duplicates_multiline_values_and_nonlogin_rows(self):
        result, _, rows = self.prepare(['UserId', 'Operation', 'SuspiciousLogin.Reasons'], [
            ['user@example.com', 'UserLoggedIn', 'First reason, "quoted"\nSecond reason'],
            ['user@example.com', 'Send', ''], ['user@example.com', 'Send', ''],
        ])
        self.assertEqual(result['rowCount'], 3)
        self.assertEqual(rows[0]['Risk Reasons (Heuristic)'], 'First reason, "quoted"\nSecond reason')
        self.assertEqual(rows[1], rows[2])
        self.assertEqual(rows[1]['Operation'], 'Send')

    def test_missing_header_user_and_same_path_are_rejected(self):
        source, output = self.root / 'source.csv', self.root / 'result.csv'
        source.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'header'):
            prepare_signin_review(source, output)
        source.write_bytes(b'User,Operation\nexample,UserLoggedIn\n')
        with self.assertRaisesRegex(ValueError, 'User column missing'):
            prepare_signin_review(source, output)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, 'different files'):
            prepare_signin_review(source, source)

    def test_header_only_and_progress(self):
        result, headers, rows = self.prepare(['UserId'], [])
        self.assertEqual(result['rowCount'], 0)
        self.assertEqual(headers[1], 'User')
        self.assertEqual(rows, [])
        source = self.root / 'many.csv'
        source.write_bytes(b'UserId\n' + b'user@example.com\n' * 1001)
        updates = []
        result = prepare_signin_review(source, self.root / 'many-review.csv', updates.append)
        self.assertEqual(updates, [500, 1000, 1001])
        self.assertEqual(result['rowCount'], 1001)

    def test_async_case_scoped_result_preserves_source_hash_after_reopen(self):
        store = CaseStore(self.root / 'cases')
        case = store.create_case('Synthetic sign-in preparation')
        raw = b'UserId,Operation\nuser@example.com,UserLoggedIn\n'
        job = store.receive_ual_stream(case['id'], 'login.csv', io.BytesIO(raw), len(raw), 'client-review.csv', signin_review=True)
        deadline = time.monotonic() + 10
        while job['phase'] not in ('complete', 'failed') and time.monotonic() < deadline:
            time.sleep(.01)
            job = store.import_status(case['id'], job['id'])
        self.assertEqual(job['phase'], 'complete', job)
        self.assertEqual(job['meta']['rowCount'], 1)
        self.assertEqual(job['meta']['sourceSha256'], hashlib.sha256(raw).hexdigest())
        reopened = CaseStore(self.root / 'cases')
        path, meta = reopened.signin_review_output(case['id'], job['id'])
        self.assertEqual(meta['outputFilename'], 'client-review.csv')
        self.assertTrue(path.read_bytes().startswith(b'\xef\xbb\xbf'))
        self.assertEqual(store.ual_datasets(case['id']), [])
        other = store.create_case('Other synthetic case')
        with self.assertRaises(KeyError):
            reopened.signin_review_output(other['id'], job['id'])
