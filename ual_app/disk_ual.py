import csv
import codecs
import hashlib
import json
import sqlite3
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from .core import ALIASES, ACTIVITY_CATEGORIES, compile_query, ip_columns, matches_event_category, normalize_ip, row_columns


MAX_UAL_BYTES = 8 * 1024 ** 3
STREAM_FORMATS = {'.csv', '.txt', '.jsonl', '.ndjson'}


@contextmanager
def connection(path):
    db = sqlite3.connect(str(path), timeout=60)
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA temp_store=FILE')
    try:
        yield db
    finally:
        db.close()


def iter_source(path):
    path = Path(path)
    with path.open('rb') as raw:
        sample = raw.read(8192)
    if sample.startswith((b'\xff\xfe', b'\xfe\xff')):
        encoding = 'utf-16'
    elif b'\x00' in sample:
        encoding = 'utf-16-be' if sample[:1] == b'\x00' else 'utf-16-le'
    else:
        try:
            decoder = codecs.getincrementaldecoder('utf-8-sig')()
            with path.open('rb') as raw:
                while chunk := raw.read(1024 * 1024):
                    decoder.decode(chunk)
                decoder.decode(b'', final=True)
            encoding = 'utf-8-sig'
        except UnicodeDecodeError:
            encoding = 'cp1252'
    with path.open('r', encoding=encoding, newline='') as handle:
        if path.suffix.casefold() in {'.jsonl', '.ndjson'}:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f'Invalid JSON on line {number}: {error.msg}') from error
                yield value if isinstance(value, dict) else {'value': value}
            return
        sample_text = handle.read(8192).replace('\x00', '')
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample_text, delimiters=',\t;|')
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader((line.replace('\x00', '') for line in handle), dialect=dialect)
        for row in reader:
            if None in row:
                raise ValueError(f'CSV record ending on line {reader.line_num} has more values than headers')
            yield row


class DiskMetrics:
    def __init__(self, db, columns):
        self.db = db
        self.columns = columns
        self.ips = ip_columns(columns)
        self.rows = self.tagged = 0
        db.execute('CREATE TABLE IF NOT EXISTS indicators(kind TEXT, value TEXT, PRIMARY KEY(kind,value)) WITHOUT ROWID')

    def add(self, row):
        self.rows += 1
        self.tagged += bool(row.get('Review.Tag'))
        identity = next((str(row.get(field)).strip() for field in ALIASES['user'] if str(row.get(field) or '').strip()), '')
        values = [('user', identity.casefold())] if identity else []
        values.extend(('message', value.strip()) for value in str(row.get('InternetMessageIDs', '')).split(';') if value.strip())
        values.extend(('ip', ip) for column in self.ips if (ip := normalize_ip(row.get(column))))
        self.db.executemany('INSERT OR IGNORE INTO indicators VALUES (?,?)', values)

    def result(self):
        counts = dict(self.db.execute('SELECT kind, COUNT(*) FROM indicators GROUP BY kind'))
        return {'rows': self.rows, 'columns': len(self.columns), 'users': counts.get('user', 0),
                'ips': counts.get('ip', 0), 'messageIds': counts.get('message', 0), 'tagged': self.tagged}


class DiskRows:
    def __init__(self, path, columns=None, decorate=None, predicate=None, revision='base'):
        self.path = Path(path)
        self.decorate = decorate or (lambda row: row)
        self.predicate = predicate
        self.revision = revision
        self.selection_key = None
        self.last_query_key = None
        if columns is None:
            with connection(self.path) as db:
                columns = json.loads(db.execute("SELECT value FROM metadata WHERE key='columns'").fetchone()[0])
        self.columns = list(columns)

    def where(self, predicate):
        old = self.predicate
        return DiskRows(self.path, self.columns, self.decorate, lambda row: (old is None or old(row)) and predicate(row), self.revision)

    def _open(self, db):
        if self.selection_key and db.execute("SELECT 1 FROM sqlite_master WHERE name='review_queries'").fetchone():
            if db.execute('SELECT 1 FROM review_queries WHERE key=?', (self.selection_key,)).fetchone():
                db.create_function('selection_key', 0, lambda: self.selection_key)
                return ' WHERE id IN (SELECT row_id FROM review_matches WHERE key=selection_key())'
        db.create_function('review_match', 1, lambda raw: int(self.predicate(self.decorate(json.loads(raw)))))
        return ' WHERE review_match(data)' if self.predicate else ''

    def __iter__(self):
        with connection(self.path) as db:
            for raw, in db.execute('SELECT data FROM records' + self._open(db) + ' ORDER BY id'):
                yield self.decorate(json.loads(raw))

    def __len__(self):
        with connection(self.path) as db:
            return db.execute('SELECT COUNT(*) FROM records' + self._open(db)).fetchone()[0]

    def __bool__(self):
        with connection(self.path) as db:
            return db.execute('SELECT 1 FROM records' + self._open(db) + ' LIMIT 1').fetchone() is not None

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = item.start or 0
            stop = item.stop if item.stop is not None else len(self)
            if start < 0 or stop < 0 or item.step not in (None, 1):
                raise ValueError('Unsupported disk-backed row slice')
            return self.page(start, max(0, stop - start))
        if item < 0:
            item += len(self)
        found = self.page(item, 1)
        if not found:
            raise IndexError(item)
        return found[0]

    def page(self, offset, limit, field='', direction='asc', timestamp=None):
        with connection(self.path) as db:
            where = self._open(db)
            order = 'id'
            if field:
                def key(raw):
                    value = self.decorate(json.loads(raw)).get(field, '')
                    text = str(value if value is not None else '').strip()
                    if not text:
                        return json.dumps([2, 0, ''])
                    if timestamp:
                        parsed = timestamp(value)
                        return json.dumps([0, parsed, ''] if parsed is not None else [1, 0, text.casefold()])
                    if field.endswith('.Risk'):
                        return json.dumps([0, {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(text.casefold(), 0), text.casefold()])
                    if field == '_Row' or field.endswith(('.Score', '.DomainAgeDays')):
                        try:
                            return json.dumps([0, float(text), ''])
                        except ValueError:
                            return json.dumps([1, 0, text])
                    return json.dumps([0, 0, text])
                db.create_function('review_sort', 1, key)
                suffix = ' DESC' if direction == 'desc' else ' ASC'
                order = "json_extract(review_sort(data),'$[0]') ASC, json_extract(review_sort(data),'$[1]')" + suffix + ", json_extract(review_sort(data),'$[2]')" + suffix + ', id'
            sql = 'SELECT data FROM records' + where + ' ORDER BY ' + order + ' LIMIT ? OFFSET ?'
            return [self.decorate(json.loads(raw)) for raw, in db.execute(sql, (limit, max(0, offset)))]

    def summary(self):
        operations = Counter()
        categories = Counter()
        with connection('') as temporary:
            metrics = DiskMetrics(temporary, self.columns)
            for row in self:
                metrics.add(row)
                operations[str(row.get('Operation', 'Unknown') or 'Unknown')] += 1
                for category in ACTIVITY_CATEGORIES:
                    categories[category] += matches_event_category(row, category)
            return {**metrics.result(), 'operations': [{'name': key, 'count': count} for key, count in operations.most_common(12)],
                    'categories': {key: categories[key] for key in ACTIVITY_CATEGORIES}}

    def review(self, query, category, operation, selected_operation=''):
        key = hashlib.sha256(json.dumps([self.revision, query, category, operation, selected_operation]).encode()).hexdigest()
        with connection(self.path) as cache:
            cache.execute('CREATE TABLE IF NOT EXISTS review_queries(key TEXT PRIMARY KEY, metrics TEXT, facets TEXT)')
            cache.execute('CREATE TABLE IF NOT EXISTS review_matches(key TEXT, row_id INTEGER, PRIMARY KEY(key,row_id)) WITHOUT ROWID')
            cached = cache.execute('SELECT metrics,facets FROM review_queries WHERE key=?', (key,)).fetchone()
            if cached:
                self.last_query_key = key
                return json.loads(cached[0]), json.loads(cached[1])
            cache.commit()
            metrics, facets = self._build_review(query, category, operation, selected_operation, cache, key)
            cache.execute('INSERT OR REPLACE INTO review_queries VALUES (?,?,?)', (key, json.dumps(metrics), json.dumps(facets)))
            stale = [item[0] for item in cache.execute('SELECT key FROM review_queries WHERE key!=? ORDER BY rowid DESC LIMIT -1 OFFSET 3', (key,))]
            for old_key in stale:
                cache.execute('DELETE FROM review_matches WHERE key=?', (old_key,))
                cache.execute('DELETE FROM review_queries WHERE key=?', (old_key,))
            cache.commit()
        self.last_query_key = key
        return metrics, facets

    def _build_review(self, query, category, operation, selected_operation, cache, key):
        predicate = compile_query(query)
        operations, categories = Counter(), Counter()
        query_total = category_total = 0
        with connection('') as temporary:
            metrics = DiskMetrics(temporary, self.columns)
            for row in self:
                if not predicate(row):
                    continue
                query_total += 1
                for name in ACTIVITY_CATEGORIES:
                    categories[name] += matches_event_category(row, name)
                if not matches_event_category(row, category):
                    continue
                category_total += 1
                if row.get('Operation'):
                    operations[str(row['Operation'])] += 1
                if not operation or str(row.get('Operation', '')) == operation:
                    metrics.add(row)
                    cache.execute('INSERT OR IGNORE INTO review_matches VALUES (?,?)', (key, int(row['_Row'])))
            top = [{'name': name, 'count': count} for name, count in operations.most_common(12)]
            if selected_operation in operations and selected_operation not in {item['name'] for item in top}:
                top.append({'name': selected_operation, 'count': operations[selected_operation]})
            return metrics.result(), {'all': query_total, 'categories': {key: categories[key] for key in ACTIVITY_CATEGORIES},
                                      'operationTotal': category_total, 'operations': top}

    def value_facets(self, column, search='', offset=0, limit=200):
        offset, limit = max(0, int(offset)), min(500, max(1, int(limit)))
        needle = str(search or '').casefold()
        with connection('') as temporary:
            temporary.execute('CREATE TABLE vals(value TEXT PRIMARY KEY, count INTEGER) WITHOUT ROWID')
            matching_rows = 0
            for row in self:
                matching_rows += 1
                value = '' if row.get(column) is None else str(row.get(column, ''))
                temporary.execute('INSERT INTO vals VALUES (?,1) ON CONFLICT(value) DO UPDATE SET count=count+1', (value,))
            temporary.create_function('value_matches', 1, lambda value: int(not needle or needle in value.casefold()))
            temporary.create_function('fold', 1, str.casefold)
            total = temporary.execute('SELECT COUNT(*) FROM vals').fetchone()[0]
            matching = temporary.execute('SELECT COUNT(*) FROM vals WHERE value_matches(value)').fetchone()[0]
            values = [{'value': value, 'label': value or '(empty)', 'count': count} for value, count in temporary.execute(
                'SELECT value,count FROM vals WHERE value_matches(value) ORDER BY count DESC,fold(value) LIMIT ? OFFSET ?', (limit, offset))]
            return {'totalUnique': total, 'matchingUnique': matching, 'matchingRows': matching_rows, 'offset': offset,
                    'hasMore': offset + len(values) < matching, 'values': values}
