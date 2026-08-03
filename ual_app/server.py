import argparse
import csv
import io
import json
import mimetypes
import re
import traceback
from collections import Counter
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .app_mapping import UNKNOWN_APP, app_reference
from .client_xlsx import client_xlsx_bytes
from .core import ACTIVITY_CATEGORIES, compile_query, email_domains, enrich_domains_rdap, enrich_ips_ipapi, ip_columns, matches_event_category, message_trace_ip_columns, normalize_ip, row_columns, summarize_metrics
from .email_collection import collect_emails, csv_targets, manual_targets
from .store import CaseStore

APP_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = APP_ROOT / "static"
STORE = CaseStore(APP_ROOT / "cases")
SORTABLE_FIELDS = {"CreationTime", "Received", "_Row", "Travel.Risk", "Travel.Score",
                   "MessageTraceHunt.Risk", "MessageTraceHunt.Score", "MessageTraceHunt.DomainAgeDays"}
CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
IP_API_CACHE_PROVIDERS = ("ip-api.com", "ip-api.com Pro", "Local")


class MultipartField:
    def __init__(self, value="", filename="", payload=b""):
        self.value = value
        self.filename = filename
        self.file = io.BytesIO(payload)


class MultipartForm:
    def __init__(self, fields):
        self.fields = fields

    def __contains__(self, name):
        return name in self.fields

    def __getitem__(self, name):
        return self.fields[name][0]

    def getfirst(self, name, fallback=""):
        values = self.fields.get(name)
        return values[0].value if values else fallback


def parse_multipart_form(content_type, body):
    if not content_type.casefold().startswith("multipart/form-data"):
        raise ValueError("Expected multipart form data")
    if "\r" in content_type or "\n" in content_type:
        raise ValueError("Invalid multipart content type")
    try:
        header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("Invalid multipart content type") from exc
    message = BytesParser(policy=default).parsebytes(header + body)
    if not message.is_multipart() or message.defects:
        raise ValueError("Invalid multipart form data")
    fields = {}
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename() or ""
        payload = part.get_payload(decode=True) or b""
        value = ""
        if not filename:
            try:
                value = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                value = payload.decode("utf-8", errors="replace")
        fields.setdefault(name, []).append(MultipartField(value, filename, payload))
    return MultipartForm(fields)


def ip_api_credentials(body):
    api_key = str(body.get("apiKey", "") or "").strip()
    if api_key and (len(api_key) > 512 or any(character.isspace() for character in api_key)):
        raise ValueError("The commercial IP-API key is invalid")
    if not api_key and body.get("acceptNonCommercialTerms") is not True:
        raise ValueError("Accept ip-api.com's non-commercial, HTTP-only free API terms or enter a commercial API key")
    return api_key


def csv_download_name(requested, fallback="ual-export"):
    value = re.split(r"[/\\]+", str(requested or ""))[-1].strip()
    if value.casefold().endswith(".csv"):
        value = value[:-4]
    value = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" ._")[:120]
    if not value:
        value = re.sub(r"[^A-Za-z0-9._ -]+", "_", str(fallback or "ual-export")).strip(" ._")[:120]
    return f"{value or 'ual-export'}.csv"


def facet_counts(query_rows, category_rows, selected_operation=""):
    operations = Counter(str(row.get("Operation", "")) for row in category_rows if row.get("Operation"))
    top_operations = [{"name": name, "count": count} for name, count in operations.most_common(12)]
    if selected_operation and selected_operation in operations and selected_operation not in {item["name"] for item in top_operations}:
        top_operations.append({"name": selected_operation, "count": operations[selected_operation]})
    return {
        "all": len(query_rows),
        "categories": {
            category: sum(1 for row in query_rows if matches_event_category(row, category))
            for category in ACTIVITY_CATEGORIES
        },
        "operationTotal": len(category_rows),
        "operations": top_operations,
    }


def is_timestamp_field(field):
    name = str(field or "")
    return name.casefold() == "received" or bool(re.search(r"time|date|timestamp", name, re.I))


def is_sortable_field(field):
    return field in SORTABLE_FIELDS or is_timestamp_field(field)


def _timestamp_sort_value(value):
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, OverflowError):
        for pattern in ("%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y"):
            try: return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc).timestamp()
            except ValueError: pass
    return None


def sort_review_rows(rows, field="", direction="asc"):
    if not is_sortable_field(field):
        return rows
    populated = [row for row in rows if str(row.get(field, "")).strip()]
    empty = [row for row in rows if not str(row.get(field, "")).strip()]
    def numeric_key(row):
        try:
            return (0, float(str(row.get(field, 0))))
        except ValueError:
            return (1, str(row.get(field, "")))
    def risk_key(row):
        value = str(row.get(field, "")).strip().casefold()
        return ({"low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0), value)
    if is_timestamp_field(field):
        parsed = [(value, row) for row in populated if (value := _timestamp_sort_value(row.get(field))) is not None]
        invalid = [row for row in populated if _timestamp_sort_value(row.get(field)) is None]
        parsed.sort(key=lambda item: item[0], reverse=direction == "desc")
        invalid.sort(key=lambda row: str(row.get(field, "")).casefold(), reverse=direction == "desc")
        return [row for _, row in parsed] + invalid + empty
    if field in ("_Row", "Travel.Score", "MessageTraceHunt.Score", "MessageTraceHunt.DomainAgeDays"):
        key = numeric_key
    elif field in ("Travel.Risk", "MessageTraceHunt.Risk"):
        key = risk_key
    else:
        key = lambda row: str(row.get(field, ""))
    populated.sort(key=key, reverse=direction == "desc")
    return populated + empty


def column_value_facets(rows, column, search="", offset=0, limit=200):
    counts = Counter("" if row.get(column) is None else str(row.get(column, "")) for row in rows)
    needle = str(search or "").casefold()
    ordered = sorted(
        ((value, count) for value, count in counts.items() if not needle or needle in value.casefold()),
        key=lambda item: (-item[1], item[0].casefold()),
    )
    offset = max(0, int(offset))
    limit = min(500, max(1, int(limit)))
    page = ordered[offset:offset + limit]
    return {
        "totalUnique": len(counts),
        "matchingUnique": len(ordered),
        "offset": offset,
        "hasMore": offset + len(page) < len(ordered),
        "values": [{"value": value, "label": value or "(empty)", "count": count} for value, count in page],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "M365InvestigatorSuite/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def json_response(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(body)
        except CLIENT_DISCONNECT_ERRORS:
            return

    def error_response(self, message, status=400):
        self.json_response({"error": str(message)}, status)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 2 * 1024 * 1024: raise ValueError("Request is too large")
        return json.loads(self.rfile.read(size) or b"{}")

    def read_multipart(self, max_bytes):
        content_type = self.headers.get("Content-Type", "")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request size") from exc
        if size <= 0:
            raise ValueError("Multipart form is empty")
        if size > max_bytes:
            raise ValueError("Request exceeds the upload limit")
        return parse_multipart_form(content_type, self.rfile.read(size))

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        try:
            if parsed.path == "/api/cases":
                return self.json_response({"cases": STORE.list()})
            if len(parts) >= 3 and parts[:2] == ["api", "cases"]:
                case_id = parts[2]
                if len(parts) == 3: return self.json_response(STORE.overview(case_id))
                if len(parts) == 4 and parts[3] == "info":
                    return self.json_response({"meta": STORE.meta(case_id)})
                if len(parts) == 4 and parts[3] == "ual-datasets":
                    return self.json_response({"datasets": STORE.ual_datasets(case_id)})
                if len(parts) == 4 and parts[3] == "message-traces":
                    return self.json_response({"traces": STORE.message_traces(case_id)})
                if len(parts) == 5 and parts[3] == "message-traces":
                    return self.json_response(STORE.message_trace_overview(case_id, parts[4]))
                if len(parts) == 6 and parts[3] == "message-traces" and parts[5] == "rows":
                    return self.get_message_trace_rows(case_id, parts[4], parse_qs(parsed.query))
                if len(parts) == 6 and parts[3] == "message-traces" and parts[5] == "column-values":
                    return self.get_message_trace_column_values(case_id, parts[4], parse_qs(parsed.query))
                if len(parts) == 6 and parts[3] == "message-traces" and parts[5] == "export":
                    return self.export_message_trace(case_id, parts[4], parse_qs(parsed.query))
                if parts[3] == "rows": return self.get_rows(case_id, parse_qs(parsed.query))
                if parts[3] == "column-values": return self.get_column_values(case_id, parse_qs(parsed.query))
                if parts[3] == "export": return self.export(case_id, parse_qs(parsed.query))
                if parts[3] == "message-subject-export": return self.export_message_subjects(case_id, parse_qs(parsed.query))
                if parts[3] == "message-ids": return self.message_ids(case_id, parse_qs(parsed.query))
            return self.static(parsed.path)
        except CLIENT_DISCONNECT_ERRORS: return
        except KeyError as exc: self.error_response(exc.args[0], 404)
        except ValueError as exc: self.error_response(exc, 400)
        except Exception as exc:
            traceback.print_exc(); self.error_response(f"Server error: {exc}", 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        try:
            if parsed.path == "/api/cases": return self.create_case()
            if parsed.path == "/api/client-xlsx": return self.create_client_xlsx()
            if parsed.path == "/api/email-collection": return self.create_email_collection()
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "ual-datasets":
                return self.create_ual_dataset(parts[2])
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces":
                return self.create_message_trace(parts[2])
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "enrich":
                return self.enrich_message_trace(parts[2], parts[4], parse_qs(parsed.query))
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "enrich-domains":
                return self.enrich_message_trace_domains(parts[2], parts[4], parse_qs(parsed.query))
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "hunt-suspicious-mail":
                return self.hunt_suspicious_message_trace(parts[2], parts[4], parse_qs(parsed.query))
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "generate-events":
                return self.generate_message_trace_events(parts[2], parts[4], parse_qs(parsed.query))
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "row-tag":
                return self.message_trace_row_tag(parts[2], parts[4])
            if len(parts) == 6 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces" and parts[5] == "bulk-row-tag":
                return self.bulk_message_trace_row_tag(parts[2], parts[4])
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "enrich":
                return self.enrich(parts[2], parse_qs(parsed.query))
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "hunt-travel":
                return self.hunt_travel(parts[2], self.read_json())
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "hunt-suspicious-logins":
                return self.hunt_suspicious_logins(parts[2], self.read_json())
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "extract-message-subjects":
                return self.extract_message_subjects(parts[2], parse_qs(parsed.query))
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "map-app-ids":
                return self.map_app_ids(parts[2], parse_qs(parsed.query))
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "generate-events":
                return self.generate_events(parts[2], parse_qs(parsed.query))
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "row-tag":
                return self.row_tag(parts[2])
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "bulk-row-tag":
                return self.bulk_row_tag(parts[2])
            self.error_response("Not found", 404)
        except CLIENT_DISCONNECT_ERRORS: return
        except KeyError as exc: self.error_response(exc.args[0], 404)
        except ValueError as exc: self.error_response(exc, 400)
        except Exception as exc:
            traceback.print_exc(); self.error_response(f"Server error: {exc}", 500)

    def do_DELETE(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            if len(parts) == 3 and parts[:2] == ["api", "cases"]:
                return self.json_response({"deleted": STORE.delete(parts[2])})
            if len(parts) == 5 and parts[:2] == ["api", "cases"] and parts[3] == "message-traces":
                return self.json_response({"deleted": STORE.delete_message_trace(parts[2], parts[4])})
            if len(parts) == 5 and parts[:2] == ["api", "cases"] and parts[3] == "ual-datasets":
                return self.json_response({"deleted": STORE.delete_ual_dataset(parts[2], parts[4])})
            self.error_response("Not found", 404)
        except CLIENT_DISCONNECT_ERRORS: return
        except KeyError as exc: self.error_response(exc.args[0], 404)
        except Exception as exc:
            traceback.print_exc(); self.error_response(f"Server error: {exc}", 500)

    def create_case(self):
        form = self.read_multipart(1024 * 1024)
        meta = STORE.create_case(form.getfirst("name", ""))
        self.json_response(meta, 201)

    def create_ual_dataset(self, case_id):
        form = self.read_multipart(252 * 1024 * 1024)
        upload = form["file"] if "file" in form else None
        if upload is None or not getattr(upload, "filename", ""): raise ValueError("Choose a UAL export file")
        raw = upload.file.read(250 * 1024 * 1024 + 1)
        meta = STORE.create_ual_dataset(case_id, upload.filename, raw, form.getfirst("name", ""))
        self.json_response({"meta": meta, **STORE.overview(meta["id"])}, 201)

    def create_client_xlsx(self):
        form = self.read_multipart(252 * 1024 * 1024)
        upload = form["file"] if "file" in form else None
        if upload is None or not getattr(upload, "filename", ""):
            raise ValueError("Choose a CSV file")
        raw = upload.file.read(250 * 1024 * 1024 + 1)
        if len(raw) > 250 * 1024 * 1024:
            raise ValueError("File exceeds the 250 MB upload limit")
        data, filename = client_xlsx_bytes(upload.filename, raw)
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def create_email_collection(self):
        form = self.read_multipart(12 * 1024 * 1024)
        if form.getfirst("authorized", "") != "yes":
            raise ValueError("Confirm that you are authorized to collect mail from the supplied mailboxes")
        mode = form.getfirst("mode", "manual")
        if mode == "csv":
            upload = form["file"] if "file" in form else None
            if upload is None or not getattr(upload, "filename", ""):
                raise ValueError("Choose a collection CSV file")
            if Path(upload.filename).suffix.casefold() != ".csv":
                raise ValueError("Email collection accepts CSV files only")
            raw = upload.file.read(10 * 1024 * 1024 + 1)
            targets = csv_targets(raw)
        elif mode == "manual":
            targets = manual_targets(form.getfirst("mailboxUPN", ""), form.getfirst("internetMessageIds", ""))
        else:
            raise ValueError("Choose manual entry or CSV upload")
        result = collect_emails(
            form.getfirst("tenantId", ""), form.getfirst("clientId", ""),
            form.getfirst("clientSecret", ""), form.getfirst("outputFolder", ""), targets,
        )
        self.json_response(result, 201)

    def create_message_trace(self, case_id):
        form = self.read_multipart(252 * 1024 * 1024)
        upload = form["file"] if "file" in form else None
        if upload is None or not getattr(upload, "filename", ""):
            raise ValueError("Choose a Message Trace CSV file")
        if Path(upload.filename).suffix.casefold() != ".csv":
            raise ValueError("Message Trace Review accepts CSV files only")
        raw = upload.file.read(250 * 1024 * 1024 + 1)
        meta = STORE.create_message_trace(case_id, upload.filename, raw, form.getfirst("name", ""))
        self.json_response({"meta": meta, **STORE.message_trace_overview(case_id, meta["id"])}, 201)

    def filtered(self, case_id, params):
        query = params.get("q", [""])[0]
        operation = params.get("operation", [""])[0]
        category = params.get("category", [""])[0]
        predicate = compile_query(query)
        rows = [r for r in STORE.rows(case_id) if predicate(r) and matches_event_category(r, category)]
        if operation: rows = [r for r in rows if str(r.get("Operation", "")) == operation]
        return rows

    def filtered_message_trace(self, case_id, trace_id, params):
        predicate = compile_query(params.get("q", [""])[0])
        return [row for row in STORE.message_trace_rows(case_id, trace_id) if predicate(row)]

    def get_message_trace_rows(self, case_id, trace_id, params):
        overview = STORE.message_trace_overview(case_id, trace_id)
        if not overview.get("exists"):
            raise ValueError("Upload a Message Trace CSV first")
        rows = self.filtered_message_trace(case_id, trace_id, params)
        sort_field = params.get("sort", [""])[0]
        sort_direction = "desc" if params.get("direction", ["asc"])[0].lower() == "desc" else "asc"
        rows = sort_review_rows(rows, sort_field, sort_direction)
        page = max(1, int(params.get("page", ["1"])[0]))
        size = min(500, max(10, int(params.get("size", ["50"])[0])))
        requested = params.get("columns", [""])[0]
        columns = overview["columns"]
        selected = [column for column in requested.split(",") if column in columns] if requested else columns[:16]
        start = (page - 1) * size
        senders = {str(row.get("SenderAddress", "")).casefold() for row in rows if row.get("SenderAddress")}
        recipients = {str(row.get("RecipientAddress", "")).casefold() for row in rows if row.get("RecipientAddress")}
        ips = {ip for row in rows for column in message_trace_ip_columns(columns) if (ip := normalize_ip(row.get(column)))}
        page_rows = [{**{key: row.get(key, "") for key in selected}, "__RowId": row.get("_Row", ""),
                      "__Tagged": bool(row.get("Review.Tag"))} for row in rows[start:start + size]]
        self.json_response({"rows": page_rows, "total": len(rows), "page": page, "size": size,
                            "columns": columns, "selected": selected,
                            "sort": sort_field if is_sortable_field(sort_field) else "", "direction": sort_direction,
                            "metrics": {"rows": len(rows), "columns": len(columns), "senders": len(senders),
                                        "recipients": len(recipients), "ips": len(ips),
                                        "tagged": sum(1 for row in rows if row.get("Review.Tag"))}})

    def get_message_trace_column_values(self, case_id, trace_id, params):
        column = params.get("column", [""])[0]
        if column not in STORE.message_trace_overview(case_id, trace_id)["columns"]:
            raise ValueError("Choose a valid MTL column")
        rows = self.filtered_message_trace(case_id, trace_id, params)
        result = column_value_facets(
            rows, column, params.get("search", [""])[0],
            params.get("offset", ["0"])[0], params.get("limit", ["200"])[0],
        )
        self.json_response({**result, "column": column, "matchingRows": len(rows)})

    def get_rows(self, case_id, params):
        all_rows = STORE.rows(case_id)
        query = params.get("q", [""])[0]
        operation = params.get("operation", [""])[0]
        category = params.get("category", [""])[0]
        predicate = compile_query(query)
        query_rows = [row for row in all_rows if predicate(row)]
        category_rows = [row for row in query_rows if matches_event_category(row, category)]
        rows = category_rows
        if operation:
            rows = [row for row in category_rows if str(row.get("Operation", "")) == operation]
        sort_field = params.get("sort", [""])[0]
        sort_direction = "desc" if params.get("direction", ["asc"])[0].lower() == "desc" else "asc"
        rows = sort_review_rows(rows, sort_field, sort_direction)
        page = max(1, int(params.get("page", ["1"])[0]))
        size = min(500, max(10, int(params.get("size", ["50"])[0])))
        overview = STORE.overview(case_id)
        columns = overview["columns"]
        requested = params.get("columns", [""])[0]
        selected = [c for c in requested.split(",") if c in columns] if requested else columns[:14]
        start = (page - 1) * size
        unfiltered = not query.strip() and not category and not operation
        filtered_summary = overview["summary"] if unfiltered else summarize_metrics(rows)
        page_rows = [{**{k: row.get(k, "") for k in selected}, "__RowId": row.get("_Row", ""),
                      "__Tagged": bool(row.get("Review.Tag"))} for row in rows[start:start + size]]
        return self.json_response({"rows": page_rows,
                                   "total": len(rows), "page": page, "size": size, "columns": columns,
                                   "selected": selected, "sort": sort_field if is_sortable_field(sort_field) else "",
                                   "direction": sort_direction, "metrics": {
                                       key: filtered_summary[key]
                                       for key in ("rows", "columns", "users", "ips", "messageIds", "tagged")
                                   },
                                   "facets": facet_counts(query_rows, category_rows, operation)})

    def row_tag(self, case_id):
        body = self.read_json()
        tagged = body.get("tagged")
        if not isinstance(tagged, bool):
            raise ValueError("Tagged must be true or false")
        self.json_response(STORE.set_row_tag(case_id, body.get("row"), tagged))

    def bulk_row_tag(self, case_id):
        body = self.read_json()
        tagged = body.get("tagged")
        if not isinstance(tagged, bool):
            raise ValueError("Tagged must be true or false")
        query = str(body.get("q", "")).strip()
        category = str(body.get("category", "")).strip()
        operation = str(body.get("operation", "")).strip()
        if not query and not category and not operation:
            raise ValueError("Apply a query, category, or operation filter before tagging rows")
        rows = self.filtered(case_id, {"q": [query], "category": [category], "operation": [operation]})
        self.json_response(STORE.set_row_tags(case_id, [row.get("_Row") for row in rows], tagged))

    def get_column_values(self, case_id, params):
        column = params.get("column", [""])[0]
        if column not in STORE.overview(case_id)["columns"]:
            raise ValueError("Choose a valid column")
        rows = self.filtered(case_id, params)
        result = column_value_facets(
            rows,
            column,
            params.get("search", [""])[0],
            params.get("offset", ["0"])[0],
            params.get("limit", ["200"])[0],
        )
        self.json_response({"column": column, "matchingRows": len(rows), **result})

    def message_ids(self, case_id, params):
        ids = sorted({x.strip() for r in self.filtered(case_id, params) for x in str(r.get("InternetMessageIDs", "")).split(";") if x.strip()})
        return self.json_response({"messageIds": ids, "count": len(ids)})

    def export(self, case_id, params):
        rows = self.filtered(case_id, params)
        data = STORE.csv_bytes(rows, STORE.enrichment(case_id))
        filename = csv_download_name(params.get("filename", [""])[0], f"{case_id}-ual-export")
        self.send_response(200); self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def export_message_subjects(self, case_id, params):
        include_size = params.get("includeSize", [""])[0].casefold() in {"1", "true", "yes"}
        rows = STORE.exported_message_subject_pairs(case_id, self.filtered(case_id, params), include_size)
        output = io.StringIO()
        fields = ["InternetMessageId", "Subject"] + (["SizeInBytes"] if include_size else [])
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
        data = output.getvalue().encode("utf-8-sig")
        meta = STORE.meta(case_id)
        fallback = meta.get("ualName") or Path(meta.get("sourceFile", "ual")).stem
        filename = csv_download_name(params.get("filename", [""])[0], f"{fallback}-message-ids-subjects")
        self.send_response(200); self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)

    def export_message_trace(self, case_id, trace_id, params):
        overview = STORE.message_trace_overview(case_id, trace_id)
        if not overview.get("exists"):
            raise ValueError("Upload a Message Trace CSV first")
        rows = self.filtered_message_trace(case_id, trace_id, params)
        data = STORE.csv_bytes(rows, {})
        fallback = overview.get("meta", {}).get("name") or f"{trace_id}-mtl-export"
        filename = csv_download_name(params.get("filename", [""])[0], f"{fallback}-mtl-export")
        self.send_response(200); self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)

    def enrich(self, case_id, params):
        body = self.read_json()
        api_key = ip_api_credentials(body)
        selected_column = str(body.get("column", "")).strip()
        rows = self.filtered(case_id, params)
        if not rows: raise ValueError("The current filters contain no rows to enrich")
        columns = STORE.overview(case_id)["columns"]
        candidates = [selected_column] if selected_column in columns else ip_columns(columns)
        if not candidates: raise ValueError("No IP column was detected; choose an IP column")
        ips = sorted({ip for row in rows for col in candidates if (ip := normalize_ip(row.get(col)))})
        if not ips: raise ValueError("No valid IP addresses were found in the current filtered rows")
        cache = STORE.enrichment(case_id)
        pending = [ip for ip in ips if ip not in cache or cache[ip].get("Lookup_Status") == "Failed" or cache[ip].get("Provider") not in IP_API_CACHE_PROVIDERS]
        cache.update(enrich_ips_ipapi(pending, api_key=api_key))
        STORE.save_enrichment(case_id, cache)
        for column in candidates: STORE.save_enrichment_column(case_id, column)
        enriched_rows = STORE.rows(case_id)
        self.json_response({"found": len(ips), "lookedUp": len(pending), "results": cache,
                            "columns": row_columns(enriched_rows), "enrichedColumns": candidates,
                            "provider": "commercial" if api_key else "free"})

    def enrich_message_trace(self, case_id, trace_id, params):
        body = self.read_json()
        api_key = ip_api_credentials(body)
        overview = STORE.message_trace_overview(case_id, trace_id)
        if not overview.get("exists"):
            raise ValueError("Upload a Message Trace CSV first")
        rows = self.filtered_message_trace(case_id, trace_id, params)
        if not rows:
            raise ValueError("The current Message Trace filters contain no rows to enrich")
        selected_column = str(body.get("column", "")).strip()
        candidates = [selected_column] if selected_column in overview["columns"] else message_trace_ip_columns(overview["columns"])
        if not candidates:
            raise ValueError("No IP column was detected in the Message Trace CSV")
        ips = sorted({ip for row in rows for column in candidates if (ip := normalize_ip(row.get(column)))})
        if not ips:
            raise ValueError("No valid IP addresses were found in the filtered Message Trace rows")
        cache = STORE.message_trace_enrichment(case_id, trace_id)
        pending = [ip for ip in ips if ip not in cache or cache[ip].get("Lookup_Status") == "Failed" or cache[ip].get("Provider") not in IP_API_CACHE_PROVIDERS]
        cache.update(enrich_ips_ipapi(pending, api_key=api_key))
        STORE.save_message_trace_enrichment(case_id, trace_id, cache, candidates)
        updated = STORE.message_trace_overview(case_id, trace_id)
        self.json_response({"found": len(ips), "lookedUp": len(pending), "columns": updated["columns"],
                            "enrichedColumns": updated["enrichmentColumns"],
                            "provider": "commercial" if api_key else "free"})

    def enrich_message_trace_domains(self, case_id, trace_id, params):
        body = self.read_json()
        overview = STORE.message_trace_overview(case_id, trace_id)
        rows = self.filtered_message_trace(case_id, trace_id, params)
        if not rows:
            raise ValueError("The current Message Trace filters contain no rows to enrich")
        available = [column for column in ("SenderAddress", "RecipientAddress") if column in overview["columns"]]
        selected = str(body.get("column", "")).strip()
        candidates = [selected] if selected in available else available
        if not candidates:
            raise ValueError("No SenderAddress or RecipientAddress column was detected")
        domains = sorted({domain for row in rows for column in candidates for domain in email_domains(row.get(column))})
        if not domains:
            raise ValueError("No valid email domains were found in the filtered Message Trace rows")
        cache = STORE.message_trace_domain_enrichment(case_id, trace_id)
        pending = [domain for domain in domains if domain not in cache or cache[domain].get("Lookup_Status") == "Failed"]
        cache.update(enrich_domains_rdap(pending))
        STORE.save_message_trace_domain_enrichment(case_id, trace_id, cache, candidates)
        updated = STORE.message_trace_overview(case_id, trace_id)
        self.json_response({"found": len(domains), "lookedUp": len(pending), "columns": updated["columns"],
                            "enrichedColumns": updated["domainEnrichmentColumns"]})

    def hunt_suspicious_message_trace(self, case_id, trace_id, params):
        body = self.read_json()
        use_domain = body.get("useDomainAge") is not False
        overview = STORE.message_trace_overview(case_id, trace_id)
        if not overview.get("domainEnrichmentColumns"):
            raise ValueError("Run Message Trace domain enrichment before hunting suspicious mail")
        try:
            max_age_days = min(3650, max(1, int(body.get("maxAgeDays", 365))))
        except (TypeError, ValueError):
            raise ValueError("Domain age must be a number of days between 1 and 3650")
        registered_after = str(body.get("registeredAfter", "")).strip()
        registered_before = str(body.get("registeredBefore", "")).strip()
        for label, value in (("registration start", registered_after), ("registration end", registered_before)):
            if value:
                try: datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError: raise ValueError(f"Invalid {label} date")
        if registered_after and registered_before and registered_after > registered_before:
            raise ValueError("Registration start must be before registration end")
        raw_keywords = body.get("keywords", [])
        keywords = raw_keywords if isinstance(raw_keywords, list) else re.split(r"[,\n]", str(raw_keywords))
        keywords = [str(value).strip() for value in keywords if str(value).strip()]
        use_services = body.get("useServiceDomains") is not False
        raw_services = body.get("serviceDomains", [])
        service_domains = raw_services if isinstance(raw_services, list) else re.split(r"[,\n]", str(raw_services))
        service_domains = [str(value).strip() for value in service_domains if str(value).strip()] if use_services else []
        if not use_domain and not keywords and not service_domains:
            raise ValueError("Enable domain age, provide a subject keyword, or provide a service sender domain")
        rows = self.filtered_message_trace(case_id, trace_id, params)
        if not rows:
            raise ValueError("The current Message Trace filters contain no rows to hunt")
        analysis = STORE.hunt_message_trace(
            case_id, trace_id, rows, use_domain_age=use_domain, max_age_days=max_age_days,
            registered_after=registered_after, registered_before=registered_before, keywords=keywords,
            service_domains=service_domains,
        )
        updated = STORE.message_trace_overview(case_id, trace_id)
        self.json_response({"findingCount": analysis["findingCount"], "domainHitCount": analysis["domainHitCount"],
                            "subjectHitCount": analysis["subjectHitCount"],
                            "serviceHitCount": analysis["serviceHitCount"], "columns": updated["columns"]})

    def generate_message_trace_events(self, case_id, trace_id, params):
        rows = self.filtered_message_trace(case_id, trace_id, params)
        if not rows:
            raise ValueError("The current Message Trace filters contain no rows for Event generation")
        generated = STORE.enable_message_trace_events(case_id, trace_id, [row.get("_Row") for row in rows])
        updated = STORE.message_trace_overview(case_id, trace_id)
        self.json_response({"generatedAt": generated["generatedAt"], "rowCount": generated["matched"],
                            "eventRowCount": generated["enabled"], "columns": updated["columns"]})

    def message_trace_row_tag(self, case_id, trace_id):
        body = self.read_json()
        tagged = body.get("tagged")
        if not isinstance(tagged, bool):
            raise ValueError("Tagged must be true or false")
        result = STORE.set_message_trace_row_tags(case_id, trace_id, [body.get("row")], tagged)
        result["row"] = str(body.get("row", ""))
        self.json_response(result)

    def bulk_message_trace_row_tag(self, case_id, trace_id):
        body = self.read_json()
        tagged = body.get("tagged")
        if not isinstance(tagged, bool):
            raise ValueError("Tagged must be true or false")
        query = str(body.get("q", "")).strip()
        if not query:
            raise ValueError("Apply a Message Trace query before tagging filtered rows")
        rows = self.filtered_message_trace(case_id, trace_id, {"q": [query]})
        if not rows:
            raise ValueError("The current Message Trace query contains no rows to tag")
        self.json_response(STORE.set_message_trace_row_tags(case_id, trace_id, [row.get("_Row") for row in rows], tagged))

    def hunt_travel(self, case_id, options):
        analysis = STORE.hunt_impossible_travel(case_id, options)
        overview = STORE.overview(case_id)
        self.json_response({"findingCount": analysis["findingCount"], "analyzedAt": analysis["analyzedAt"],
                            "method": analysis["method"], "columns": overview["columns"]})

    def hunt_suspicious_logins(self, case_id, options):
        analysis = STORE.hunt_suspicious_logins(case_id, options)
        overview = STORE.overview(case_id)
        self.json_response({"findingCount": analysis["findingCount"], "analyzedAt": analysis["analyzedAt"],
                            "method": analysis["method"], "columns": overview["columns"]})

    def extract_message_subjects(self, case_id, params):
        STORE.extract_message_subjects(case_id)
        rows = self.filtered(case_id, params)
        pair_count = sum(len([item for item in str(row.get("MessageSubject.InternetMessageIDs", "")).split(";") if item.strip()]) for row in rows)
        rows_with_pairs = sum(1 for row in rows if row.get("MessageSubject.InternetMessageIDs"))
        overview = STORE.overview(case_id)
        self.json_response({"pairCount": pair_count, "rowCount": rows_with_pairs, "columns": overview["columns"]})

    def map_app_ids(self, case_id, params):
        rows = self.filtered(case_id, params)
        mapping_columns = [column for column in row_columns(rows) if column.startswith("AppMapping.")]
        mappings = [{"source": column[len("AppMapping."):], "column": column} for column in mapping_columns]
        mapped_rows = sum(1 for row in rows if any(row.get(column) for column in mapping_columns))
        known = sum(1 for row in rows for column in mapping_columns if row.get(column) and row.get(column) != UNKNOWN_APP)
        unlisted = sum(1 for row in rows for column in mapping_columns if row.get(column) == UNKNOWN_APP)
        reference = app_reference()
        self.json_response({"mappings": mappings, "mappedRows": mapped_rows, "known": known, "unlisted": unlisted,
                            "referenceCount": len(reference["apps"]), "source": reference["source"]})

    def generate_events(self, case_id, params):
        rows = self.filtered(case_id, params)
        if not rows: raise ValueError("The current filters contain no rows for Event generation")
        generated = STORE.enable_events(case_id, [row.get("_Row") for row in rows])
        overview = STORE.overview(case_id)
        self.json_response({"generatedAt": generated["generatedAt"], "rowCount": generated["matched"],
                            "eventRowCount": generated["enabled"],
                            "columns": overview["columns"]})

    def static(self, path):
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC_ROOT / relative).resolve()
        if STATIC_ROOT not in target.parents and target != STATIC_ROOT: return self.error_response("Not found", 404)
        if not target.is_file(): target = STATIC_ROOT / "index.html"
        body = target.read_bytes(); content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Local M365 UAL investigation workbench")
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"M365 Investigator Suite running at http://{args.host}:{args.port}")
    print(f"Cases stored in {STORE.root}")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping server")
    finally: server.server_close()
