import csv
import http.client
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode
from http.server import ThreadingHTTPServer

from ual_app import server
from ual_app.store import CaseStore


class DiskUalHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CaseStore(Path(self.temp.name))
        self.case = self.store.create_case('Synthetic HTTP test')
        self.patcher = patch.object(server, 'STORE', self.store)
        self.patcher.start()
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        self.patcher.stop()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        client = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=10)
        client.request(method, path, body, headers or {})
        response = client.getresponse()
        data = response.read()
        content_type = response.getheader('Content-Type', '')
        status = response.status
        client.close()
        return status, json.loads(data) if 'application/json' in content_type else data

    def import_rows(self):
        raw = b'CreationTime,Operation,UserId\n' + b''.join(
            f'2026-01-{index % 28 + 1:02}T12:00:00Z,{"MailItemsAccessed" if index % 2 else "FileAccessed"},user{index % 3}@example.com\n'.encode()
            for index in range(125))
        status, job = self.request('POST', f'/api/cases/{self.case["id"]}/ual-stream?filename=synthetic.csv&name=HTTP', raw,
                                   {'Content-Type': 'application/octet-stream'})
        self.assertEqual(status, 202)
        deadline = time.monotonic() + 10
        while job['phase'] not in ('complete', 'failed') and time.monotonic() < deadline:
            time.sleep(.01)
            status, job = self.request('GET', f'/api/cases/{self.case["id"]}/ual-imports/{job["id"]}')
        self.assertEqual(job['phase'], 'complete', job)
        return job['id']

    def test_end_to_end_import_page_query_cache_tag_and_filtered_export(self):
        identifier = self.import_rows()
        status, overview = self.request('GET', f'/api/cases/{identifier}')
        self.assertEqual(status, 200)
        self.assertEqual(overview['summary']['rows'], 125)
        params = {'q': 'operation:=MailItemsAccessed', 'category': 'email_access', 'columns': '_Row,CreationTime,UserId', 'size': 10, 'page': 2}
        path = f'/api/cases/{identifier}/rows?{urlencode(params)}'
        status, data = self.request('GET', path)
        self.assertEqual(status, 200)
        self.assertEqual(data['total'], 62)
        self.assertEqual(len(data['rows']), 10)
        self.assertEqual(data['rows'][0]['_Row'], 22)
        with patch.object(server.DiskRows, '_build_review', side_effect=AssertionError('Cache should avoid a new scan')):
            self.assertEqual(self.request('GET', path)[1], data)
        status, tagged = self.request('POST', f'/api/cases/{identifier}/row-tag', json.dumps({'row': 22, 'tagged': True}), {'Content-Type': 'application/json'})
        self.assertEqual(status, 200)
        self.assertEqual(tagged['taggedCount'], 1)
        tagged_params = urlencode({'q': 'Review.Tag:="Of interest"', 'columns': '_Row,Review.Tag'})
        status, data = self.request('GET', f'/api/cases/{identifier}/rows?{tagged_params}')
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['rows'][0]['_Row'], 22)
        export_params = urlencode({'q': 'Review.Tag:="Of interest"', 'filename': 'tagged'})
        status, exported = self.request('GET', f'/api/cases/{identifier}/export?{export_params}')
        records = list(csv.DictReader(io.StringIO(exported.decode('utf-8-sig'))))
        self.assertEqual(status, 200)
        self.assertEqual([record['_Row'] for record in records], ['22'])
        self.assertEqual(records[0]['Review.Tag'], 'Of interest')
        status, values = self.request('GET', f'/api/cases/{identifier}/column-values?column=UserId&limit=2')
        self.assertEqual(status, 200)
        self.assertEqual(values['totalUnique'], 3)
        self.assertEqual(len(values['values']), 2)
        self.assertTrue(values['hasMore'])

    def test_import_status_is_scoped_to_case(self):
        identifier = self.import_rows()
        other = self.store.create_case('Another synthetic case')
        status, data = self.request('GET', f'/api/cases/{other["id"]}/ual-imports/{identifier}')
        self.assertEqual(status, 404)
        self.assertEqual(data['error'], 'Import not found')

    def test_signin_review_upload_progress_download_and_case_scope(self):
        raw = b'CreationTime,UserId,Operation\n2026-01-01T00:00:00Z,user@example.com,UserLoggedIn\n'
        params = urlencode({'filename': 'logins.csv', 'output': '../../Client review.csv'})
        status, job = self.request('POST', f'/api/cases/{self.case["id"]}/signin-reviews?{params}', raw)
        self.assertEqual(status, 202)
        deadline = time.monotonic() + 10
        while job['phase'] not in ('complete', 'failed') and time.monotonic() < deadline:
            time.sleep(.01)
            status, job = self.request('GET', f'/api/cases/{self.case["id"]}/signin-reviews/{job["id"]}')
        self.assertEqual(job['phase'], 'complete', job)
        self.assertEqual(job['meta']['outputFilename'], 'Client review.csv')
        status, data = self.request('GET', f'/api/cases/{self.case["id"]}/signin-reviews/{job["id"]}/download')
        self.assertEqual(status, 200)
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
        self.assertEqual(reader.fieldnames[1], 'User')
        self.assertEqual(len(reader.fieldnames), 17)
        self.assertEqual(list(reader)[0]['User'], 'user@example.com')
        other = self.store.create_case('Other sign-in case')
        status, data = self.request('GET', f'/api/cases/{other["id"]}/signin-reviews/{job["id"]}/download')
        self.assertEqual(status, 404)
