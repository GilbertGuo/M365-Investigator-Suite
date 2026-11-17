import csv
from pathlib import Path


COLUMNS = [
    ('Time (UTC)', ('CreationTime',)),
    ('User', ('UserId', 'AuditData.UserId')),
    ('IP Address', ('ClientIP', 'SuspiciousLogin.IP', 'ActorIpAddress', 'ClientIPAddress')),
    ('Location', ('SuspiciousLogin.Location', 'GeoLocation')),
    ('ISP', ('SuspiciousLogin.ISP', 'ClientIP_IPAPI_ISP')),
    ('Operation', ('Operation',)),
    ('Result', ('ResultStatus',)),
    ('Result Detail', ('Login.ResultStatusDetail',)),
    ('Application', ('ApplicationDisplayName', 'AppMapping.ApplicationId')),
    ('Request Type', ('Login.RequestType',)),
    ('OS', ('Login.OS',)),
    ('Browser', ('Login.BrowserType',)),
    ('Device Compliant', ('Login.IsCompliant',)),
    ('Risk (Heuristic)', ('SuspiciousLogin.Risk',)),
    ('Risk Reasons (Heuristic)', ('SuspiciousLogin.Reasons',)),
    ('Session ID', ('Login.SessionId', 'SessionId')),
    ('Record ID', ('RecordId', 'Id')),
]


def first_nonempty(row, keys):
    for key in keys:
        value = row.get(key, '')
        if value and value.strip():
            return value.strip()
    return ''


def prepare_signin_review(source, output, progress=None):
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve():
        raise ValueError('Input and output must be different files')
    count = 0
    try:
        with source.open('r', encoding='utf-8-sig', newline='') as incoming:
            reader = csv.DictReader(incoming)
            headers = reader.fieldnames
            if not headers:
                raise ValueError('Input CSV has no header row')
            if 'UserId' not in headers and 'AuditData.UserId' not in headers:
                raise ValueError('User column missing: expected UserId or AuditData.UserId. Upload a flattened login CSV exported from UAL Review.')
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('w', encoding='utf-8-sig', newline='') as outgoing:
                writer = csv.DictWriter(outgoing, fieldnames=[name for name, _ in COLUMNS])
                writer.writeheader()
                for row in reader:
                    if None in row:
                        raise ValueError(f'CSV record ending on line {reader.line_num} has more values than headers')
                    writer.writerow({name: first_nonempty(row, fields) for name, fields in COLUMNS})
                    count += 1
                    if progress and count % 500 == 0:
                        progress(count)
    except UnicodeDecodeError as error:
        raise ValueError('Sign-in Review requires a UTF-8 CSV, such as Export CSV from UAL Review') from error
    except csv.Error as error:
        raise ValueError(f'Unable to read the sign-in CSV: {error}') from error
    if progress:
        progress(count)
    return {'rowCount': count, 'columns': [name for name, _ in COLUMNS]}
