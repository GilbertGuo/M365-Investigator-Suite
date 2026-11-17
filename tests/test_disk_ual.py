import csv
import hashlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from ual_app.core import compile_query, matches_event_category, summarize
from ual_app.disk_ual import DiskRows, MAX_UAL_BYTES, connection
from ual_app.server import _timestamp_sort_value, column_value_facets, facet_counts, sort_review_rows
from ual_app.store import CaseStore


class BoundedReader(io.BytesIO):
    def read(self, size=-1):
        if size < 0 or size > 1024 * 1024:
            raise AssertionError('Source must be read in bounded chunks')
        return super().read(size)


class DiskUalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = CaseStore(self.root)
        self.case = self.store.create_case('Synthetic large import')

    def tearDown(self):
        self.temporary.cleanup()

    def wait(self, job):
        deadline = time.monotonic() + 10
        while job['phase'] not in ('complete', 'failed') and time.monotonic() < deadline:
            time.sleep(.01)
            job = self.store.import_status(self.case['id'], job['id'])
        self.assertIn(job['phase'], ('complete', 'failed'))
        return job

    def upload(self, raw, filename='synthetic.csv'):
        job = self.wait(self.store.receive_ual_stream(self.case['id'], filename, BoundedReader(raw), len(raw)))
        self.assertEqual(job['phase'], 'complete', job)
        return job['meta']['id']

    def sample(self):
        buffer = io.StringIO(newline='')
        writer = csv.writer(buffer)
        writer.writerow(['CreationTime', 'Operation', 'UserId', 'AuditData'])
        for index, operation in enumerate(['UserLoggedIn', 'MailItemsAccessed', 'FileAccessed', 'MailItemsAccessed'], 1):
            writer.writerow([f'2026-01-0{index}T12:00:00Z', operation, f'user{index % 2}@example.com', json.dumps({
                'ClientIP': f'203.0.113.{index}', 'UserAgentString': 'SyntheticClient/1.0',
                'Item': {'InternetMessageId': f'<id{index}@example.com>', 'Subject': 'Document, "review"\nsecond line'},
            })])
        return buffer.getvalue().encode()

    def test_stream_import_preserves_original_and_stable_rows_after_reopen(self):
        raw = self.sample()
        identifier = self.upload(raw)
        rows = self.store.rows(identifier)
        self.assertIsInstance(rows, DiskRows)
        self.assertNotIn(identifier, self.store._rows_cache)
        self.assertEqual(len(rows), 4)
        self.assertEqual([row['_Row'] for row in rows], [1, 2, 3, 4])
        self.assertEqual(rows[1]['Mail.UserAgent'], 'SyntheticClient/1.0')
        self.assertEqual(rows[1]['Item.Subject'], 'Document, "review"\nsecond line')
        meta = self.store.meta(identifier)
        self.assertEqual(meta['sourceSha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.store._dir(identifier) / 'source' / 'synthetic.csv').read_bytes(), raw)
        self.assertFalse((self.store._dir(identifier) / 'rows.jsonl').exists())
        reopened = CaseStore(self.root)
        self.assertEqual(list(reopened.rows(identifier)), list(rows))
        self.assertEqual(reopened.overview(identifier)['summary'], summarize(list(rows)))
        self.assertEqual(self.store.ual_datasets(self.case['id'])[0]['rowCount'], 4)

    def test_query_metrics_facets_sort_and_values_match_existing_path(self):
        identifier = self.upload(self.sample())
        rows = self.store.rows(identifier)
        reference = list(rows)
        for query, category, operation in [('', '', ''), ('user:=user1@example.com OR operation:=MailItemsAccessed', '', ''),
                                           ('time:>=2026-01-02', 'email_access', 'MailItemsAccessed')]:
            query_rows = [row for row in reference if compile_query(query)(row)]
            category_rows = [row for row in query_rows if matches_event_category(row, category)]
            expected = [row for row in category_rows if not operation or row['Operation'] == operation]
            metrics, facets = rows.review(query, category, operation, operation)
            self.assertEqual(metrics, {key: value for key, value in summarize(expected).items() if key not in ('categories', 'operations')})
            self.assertEqual(facets, facet_counts(query_rows, category_rows, operation))
            selected = rows.where(lambda row: compile_query(query)(row) and matches_event_category(row, category) and (not operation or row['Operation'] == operation))
            self.assertEqual(selected.page(0, 50, 'CreationTime', 'desc', _timestamp_sort_value), sort_review_rows(expected, 'CreationTime', 'desc'))
        actual = rows.value_facets('UserId', 'USER1', 0, 1)
        expected = column_value_facets(reference, 'UserId', 'USER1', 0, 1)
        self.assertEqual(actual.pop('matchingRows'), len(reference))
        self.assertEqual(actual, expected)

    def test_tags_events_message_extraction_and_enrichment_survive_reopen(self):
        identifier = self.upload(self.sample())
        self.store.set_row_tag(identifier, 2, True)
        self.assertEqual(self.store.overview(identifier)['summary']['tagged'], 1)
        self.assertEqual([row['_Row'] for row in self.store.rows(identifier).where(compile_query('Review.Tag:="Of interest"'))], [2])
        self.store.set_row_tags(identifier, [1, 3, 999], True)
        self.store.set_row_tag(identifier, 1, False)
        self.assertEqual(self.store.overview(identifier)['summary']['tagged'], 2)
        self.store.extract_message_subjects(identifier)
        self.store.enable_events(identifier, [2])
        self.store.save_enrichment(identifier, {'203.0.113.2': {'Country': 'Canada', 'Lookup_Status': 'Success'}})
        self.store.save_enrichment_column(identifier, 'ClientIP')
        reopened = CaseStore(self.root)
        row = reopened.rows(identifier)[1]
        self.assertEqual(row['ClientIP_IPAPI_Country'], 'Canada')
        self.assertIn('Event', row)
        self.assertIn('MessageSubject.Pairs', row)
        self.assertEqual(row['Review.Tag'], 'Of interest')
        self.assertEqual(reopened.overview(identifier)['summary'], summarize(list(reopened.rows(identifier))))

    def test_utf16_and_jsonl_and_malformed_audit_data(self):
        for encoding in ('utf-16', 'utf-16-le', 'utf-16-be'):
            identifier = self.upload(self.sample().decode().encode(encoding))
            self.assertEqual(len(self.store.rows(identifier)), 4)
        identifier = self.upload(b'{"Operation":"Send","AuditData":"bad json"}\n\n{"Operation":"UserLoggedIn"}\n', 'test.jsonl')
        self.assertEqual(self.store.meta(identifier)['parseErrors'], 1)
        self.assertEqual(self.store.rows(identifier)[0]['_RawAuditData'], 'bad json')
        self.assertEqual(self.store.rows(identifier)[1]['_Row'], 2)

    def test_failed_or_partial_upload_never_publishes_dataset(self):
        job = self.wait(self.store.receive_ual_stream(self.case['id'], 'broken.jsonl', BoundedReader(b'bad\n'), 4))
        self.assertEqual(job['phase'], 'failed')
        self.assertEqual(self.store.ual_datasets(self.case['id']), [])
        self.assertFalse((self.root / self.case['id'] / 'ual' / '.imports' / job['id']).exists())
        with self.assertRaisesRegex(ValueError, 'complete file'):
            self.store.receive_ual_stream(self.case['id'], 'partial.csv', BoundedReader(b'a'), 99)
        with self.assertRaisesRegex(ValueError, '8 GiB'):
            self.store.receive_ual_stream(self.case['id'], 'big.csv', BoundedReader(b''), MAX_UAL_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'accepts'):
            self.store.receive_ual_stream(self.case['id'], 'big.json', BoundedReader(b'[]'), 2)
        self.assertEqual(self.store.ual_datasets(self.case['id']), [])

    def test_cp1252_character_after_initial_sample_is_preserved(self):
        value = 'a' * 10000 + 'Résumé – document'
        raw = ('Operation,Details\nMailItemsAccessed,' + value + '\n').encode('cp1252')
        identifier = self.upload(raw)
        self.assertEqual(self.store.rows(identifier)[0]['Details'], value)

    def test_sort_handles_invalid_and_empty_times_and_query_cache_expires_after_tag(self):
        identifier = self.upload(b'CreationTime,Operation\ninvalid,Send\n,Send\n2026-01-01T00:00:00Z,Send\n2025-01-01T00:00:00Z,Send\n')
        rows = self.store.rows(identifier)
        for direction in ('asc', 'desc'):
            self.assertEqual(rows.page(0, 10, 'CreationTime', direction, _timestamp_sort_value), sort_review_rows(list(rows), 'CreationTime', direction))
        self.assertEqual(rows.review('Review.Tag:="Of interest"', '', '')[0]['rows'], 0)
        self.store.set_row_tag(identifier, 2, True)
        changed = self.store.rows(identifier)
        self.assertEqual(changed.review('Review.Tag:="Of interest"', '', '')[0]['rows'], 1)
        selected = changed.where(compile_query('Review.Tag:="Of interest"'))
        selected.selection_key = changed.last_query_key
        self.assertEqual(selected.page(0, 10)[0]['_Row'], 2)

    def test_deleting_database_dataset_preserves_other_datasets(self):
        first = self.upload(self.sample())
        second = self.upload(self.sample())
        self.store.delete_ual_dataset(self.case['id'], first)
        self.assertEqual([item['id'] for item in self.store.ual_datasets(self.case['id'])], [second])
        self.assertEqual(len(self.store.rows(second)), 4)
        self.assertTrue(list((self.root / self.case['id'] / '.trash-ual-datasets').glob('*/rows.sqlite3')))

    def test_existing_database_backfills_inbox_rule_names_without_reupload(self):
        raw = b'Operation,OperationProperties\nUpdateInboxRules,"[{""Name"":""RuleName"",""Value"":""Review documents""}]"\n'
        identifier = self.upload(raw)
        database = self.store._dir(identifier) / 'rows.sqlite3'
        with connection(database) as db:
            row = json.loads(db.execute('SELECT data FROM records WHERE id=1').fetchone()[0])
            row.pop('InboxRule.Name', None)
            row.pop('InboxRule.Details', None)
            db.execute('UPDATE records SET data=? WHERE id=1', (json.dumps(row),))
            db.execute("DELETE FROM metadata WHERE key='inboxRuleVersion'")
            db.execute("UPDATE metadata SET value=? WHERE key='columns'", (json.dumps(list(row)),))
            db.commit()
        self.store.invalidate(identifier)
        self.assertEqual(self.store.rows(identifier)[0]['InboxRule.Name'], 'Review documents')
        self.assertIn('InboxRule.Name', self.store.overview(identifier)['columns'])
        self.assertEqual(self.store.rows(identifier).where(compile_query('InboxRule.Name:="Review documents"')).page(0, 1)[0]['_Row'], 1)
        self.assertEqual((self.store._dir(identifier) / 'source' / 'synthetic.csv').read_bytes(), raw)
        self.assertEqual(self.store.meta(identifier)['rowCount'], 1)
        with connection(database) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='inboxRuleVersion'").fetchone()[0], '1')

    def test_saved_search_events_include_query_after_reopen(self):
        raw = b'Operation,QueryText,Workload,UserId\nSearchQueryPerformed,annual report,SharePoint,user@example.com\n'
        identifier = self.upload(raw)
        self.store.enable_events(identifier, [1])
        reopened = CaseStore(self.root)
        rows = reopened.rows(identifier)
        self.assertIn('search query: annual report', rows[0]['Event'])
        self.assertEqual(rows.review('Event:*annual*', '', '')[0]['rows'], 1)
        exported = reopened.csv_bytes(rows, {})
        self.assertIn(b'search query: annual report', exported)
