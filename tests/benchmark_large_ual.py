import argparse
import csv
import io
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ual_app.core import compile_query
from ual_app.server import _timestamp_sort_value
from ual_app.store import CaseStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mib', type=int, default=64)
    args = parser.parse_args()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='m365-synthetic-benchmark-') as temporary:
        root = Path(temporary)
        source = root / 'synthetic.csv'
        record = io.StringIO(newline='')
        writer = csv.writer(record)
        writer.writerow(['2026-01-01T12:00:00Z', 'MailItemsAccessed', 'synthetic@example.com',
                         json.dumps({'ClientIP': '203.0.113.10', 'Details': 'synthetic test data ' * 5000,
                                     'Item': {'InternetMessageId': '<synthetic@example.com>', 'Subject': 'Synthetic document'}})])
        encoded = record.getvalue().encode()
        count = max(1, args.mib * 1024 ** 2 // len(encoded))
        with source.open('wb') as output:
            output.write(b'CreationTime,Operation,UserId,AuditData\r\n')
            for _ in range(count):
                output.write(encoded)
        print(json.dumps({'phase': 'generated', 'bytes': source.stat().st_size, 'rows': count}), flush=True)
        store = CaseStore(root / 'cases')
        case = store.create_case('Synthetic benchmark')
        with source.open('rb') as incoming:
            job = store.receive_ual_stream(case['id'], source.name, incoming, source.stat().st_size)
        while job['phase'] not in ('complete', 'failed'):
            print(json.dumps({'phase': job['phase'], 'rows': job['rows']}), flush=True)
            time.sleep(2)
            job = store.import_status(case['id'], job['id'])
        if job['phase'] != 'complete':
            raise RuntimeError(job)
        identifier = job['meta']['id']
        rows = store.rows(identifier)
        assert len(rows) == count
        assert store.overview(identifier)['summary']['rows'] == count
        assert len(rows.page(count - 10, 10)) == min(count, 10)
        metrics, facets = rows.review('operation:=MailItemsAccessed', 'email_access', '')
        selected = rows.where(compile_query('operation:=MailItemsAccessed'))
        selected.selection_key = rows.last_query_key
        assert metrics['rows'] == count
        assert facets['all'] == count
        assert len(selected.page(0, 10, 'CreationTime', 'desc', _timestamp_sort_value)) == min(count, 10)
        store.set_row_tag(identifier, count, True)
        assert store.rows(identifier)[count - 1]['Review.Tag'] == 'Of interest'
        assert identifier not in store._rows_cache
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_mib = peak / (1024 ** 2 if sys.platform == 'darwin' else 1024)
        print(json.dumps({'phase': 'verified', 'bytes': source.stat().st_size, 'rows': count,
                          'elapsedSeconds': round(time.monotonic() - started, 2), 'peakMemoryMiB': round(peak_mib, 2)}), flush=True)


if __name__ == '__main__':
    main()
