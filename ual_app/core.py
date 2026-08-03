import ast
import csv
import io
import ipaddress
import json
import re
import shlex
import urllib.error
import urllib.parse
import urllib.request
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

MESSAGE_ID_RE = re.compile(r"InternetMessageId['\"]?\s*:\s*['\"]<([^>]+)>", re.I)
MESSAGE_ID_VALUE_RE = re.compile(r"<?([^<>\s]+@[^<>\s]+)>?")
MESSAGE_SUBJECT_RE = re.compile(
    r"['\"]InternetMessageId['\"]\s*:\s*['\"]<?([^'\"]*?)>?['\"].*?"
    r"['\"]Subject['\"]\s*:\s*['\"]([^'\"]*)['\"]",
    re.I | re.S,
)
IP_API_FREE_BATCH_URL = "http://ip-api.com/batch"
IP_API_PRO_BATCH_URL = "https://pro.ip-api.com/batch"
IP_API_FIELDS = "status,message,country,regionName,city,isp,as,mobile,proxy,hosting,query"
IP_API_OUTPUT_FIELDS = {
    "Country": "country", "Region": "regionName", "City": "city", "ISP": "isp",
    "AS": "as", "Mobile": "mobile", "Proxy_VPN_TOR": "proxy", "Hosting": "hosting",
}
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_OUTPUT_FIELDS = [
    "Domain", "RegisteredDomain", "Registrar", "RegistrationDate", "ExpirationDate",
    "LastChangedDate", "Status", "NameServers", "DNSSEC", "Lookup_Status", "Provider", "Error",
]
EMAIL_DOMAIN_RE = re.compile(r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Z0-9.-]+)", re.I)

ALIASES = {
    "user": ["UserId", "UserKey", "MailboxOwnerUPN", "Actor.UserId", "Sender", "SenderAddress", "RecipientAddress"],
    "sender": ["Sender", "SenderAddress", "Sender Address", "FromAddress"],
    "recipient": ["Recipient", "RecipientAddress", "Recipient Address", "ToAddress"],
    "time": ["CreationTime", "Received", "ReceivedTime"],
    "operation": ["Operation"],
    "ip": ["ClientIP", "ClientIPAddress", "ActorIpAddress", "IPAddress", "OriginatingServer",
           "OriginalClientIP", "FromIP", "ToIP"],
    "clientip": ["ClientIP", "ClientIPAddress"],
    "messageid": ["InternetMessageId", "InternetMessageIDs", "Item.InternetMessageId", "MessageSubject.InternetMessageIDs",
                  "MessageId", "NetworkMessageId"],
    "subject": ["Subject", "Item.Subject", "MessageSubject.Subjects", "MessageSubject.Pairs"],
    "useragent": ["Mail.UserAgent", "ActorInfoString", "UserAgent", "ClientInfoString", "Login.UserAgent"],
    "actorinfo": ["Mail.ActorInfoString", "ActorInfoString"],
    "result": ["ResultStatus", "Result", "LogonError", "Status"],
    "workload": ["Workload"],
    "recordtype": ["RecordType"],
    "inboxrule": ["InboxRule.Name", "InboxRule.Details", "InboxRule.From", "InboxRule.MoveToFolder",
                  "InboxRule.ForwardTo", "InboxRule.RedirectTo"],
    "login": ["Login.SessionId", "Login.IsCompliant", "Login.IsManaged", "Login.IsCompliantAndManaged",
              "Login.OS", "Login.BrowserType", "Login.UserAuthenticationMethod", "Login.RequestType"],
}

MESSAGE_TRACE_HEADERS = {
    "received": "Received", "receivedtime": "Received", "receiveddatetime": "Received",
    "sender": "SenderAddress", "senderaddress": "SenderAddress", "fromaddress": "SenderAddress",
    "recipient": "RecipientAddress", "recipientaddress": "RecipientAddress", "toaddress": "RecipientAddress",
    "subject": "Subject", "messagesubject": "Subject", "status": "Status", "messageid": "MessageId",
    "internetmessageid": "MessageId", "networkmessageid": "NetworkMessageId",
    "originalclientip": "OriginalClientIP", "clientip": "ClientIP", "fromip": "FromIP", "toip": "ToIP",
    "directionality": "Directionality", "size": "Size", "messageinfo": "MessageInfo",
    "connectorid": "ConnectorId", "deliverypriority": "DeliveryPriority",
}

INBOX_RULE_FIELDS = {
    "name": "Name", "enabled": "Enabled", "priority": "Priority", "from": "From",
    "sentto": "SentTo", "subjectcontainswords": "SubjectContainsWords",
    "bodycontainswords": "BodyContainsWords", "movetofolder": "MoveToFolder",
    "forwardto": "ForwardTo", "redirectto": "RedirectTo",
    "forwardasattachmentto": "ForwardAsAttachmentTo", "deletemessage": "DeleteMessage",
    "markasread": "MarkAsRead", "stopprocessingrules": "StopProcessingRules",
}

LOGIN_DEVICE_FIELDS = {
    "sessionid": "SessionId", "deviceid": "DeviceId", "displayname": "DeviceName", "os": "OS",
    "browsertype": "BrowserType", "trusttype": "TrustType", "iscompliant": "IsCompliant",
    "ismanaged": "IsManaged", "iscompliantandmanaged": "IsCompliantAndManaged",
}
LOGIN_EXTENDED_FIELDS = {
    "resultstatusdetail": "ResultStatusDetail", "useragent": "UserAgent",
    "userauthenticationmethod": "UserAuthenticationMethod", "requesttype": "RequestType",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_safe(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return json.dumps(value, ensure_ascii=False, default=str)


def flatten(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = out if out is not None else {}
    if isinstance(value, dict):
        for key, item in value.items():
            flatten(item, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(value, list):
        out[prefix] = json.dumps(value, ensure_ascii=False, default=str)
    elif prefix:
        out[prefix] = json_safe(value)
    return out


def decode_text_upload(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig", errors="replace")
    elif raw and raw.count(b"\x00") > max(2, len(raw) // 20):
        even_nuls = raw[0::2].count(0)
        odd_nuls = raw[1::2].count(0)
        encoding = "utf-16-le" if odd_nuls >= even_nuls else "utf-16-be"
        text = raw.decode(encoding, errors="replace")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")
    return text.replace("\x00", "")


def read_upload(filename: str, raw: bytes) -> List[Dict[str, Any]]:
    suffix = Path(filename).suffix.lower()
    if suffix in (".xlsx", ".xls"):
        try:
            import pandas as pd
        except ImportError as exc:
            raise ValueError("Excel parsing requires pandas and openpyxl") from exc
        frame = pd.read_excel(io.BytesIO(raw), dtype=object)
        return [{str(k): json_safe(v) for k, v in row.items()} for row in frame.to_dict("records")]
    if suffix in (".json", ".jsonl", ".ndjson"):
        text = decode_text_upload(raw)
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = parsed.get("value", parsed.get("records", [parsed]))
            if not isinstance(parsed, list):
                raise ValueError("JSON input must be an array or contain a value/records array")
            return [x if isinstance(x, dict) else {"value": x} for x in parsed]
        except json.JSONDecodeError:
            rows = []
            for number, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"Invalid JSON on line {number}: {exc.msg}") from exc
                    rows.append(item if isinstance(item, dict) else {"value": item})
            return rows
    if suffix not in (".csv", ".txt"):
        raise ValueError("Supported file types: .csv, .xlsx, .xls, .json, .jsonl")
    text = decode_text_upload(raw)
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    return [dict(row) for row in csv.DictReader(io.StringIO(text), dialect=dialect)]


def extract_message_ids(row: Dict[str, Any], audit_raw: str = "") -> List[str]:
    found = []
    for key, value in row.items():
        if "internetmessageid" in key.lower():
            if isinstance(value, str):
                candidates = MESSAGE_ID_VALUE_RE.findall(value)
                found.extend(candidates)
    found.extend(MESSAGE_ID_RE.findall(audit_raw or ""))
    return list(dict.fromkeys(format_message_id(x) for x in found if str(x).strip()))


def format_message_id(value: Any) -> str:
    clean = str(value or "").strip().strip("<>")
    return f"<{clean}>" if clean else ""


def normalize_message_id_display(row: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in list(row.items()):
        lowered = str(key).lower()
        if lowered == "internetmessageids":
            row[key] = "; ".join(format_message_id(item) for item in str(value or "").split(";") if item.strip())
        elif lowered.endswith("internetmessageid") and value:
            row[key] = format_message_id(value)
    return row


def extract_message_subject_details(row: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    details: Dict[Tuple[str, str], str] = {}

    def add(message_id: Any, subject: Any = "", size: Any = "") -> None:
        message_id = format_message_id(message_id)
        subject = str(subject or "").strip()
        size = str(size or "").strip()
        if message_id and "@" in message_id:
            key = (message_id, subject)
            if key not in details or not details[key]:
                details[key] = size

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            lowered = {str(key).lower(): item for key, item in value.items()}
            if "internetmessageid" in lowered:
                add(lowered["internetmessageid"], lowered.get("subject", ""), lowered.get("sizeinbytes", ""))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for key, value in row.items():
        if str(key).lower().endswith("internetmessageid"):
            prefix = str(key)[:-len("InternetMessageId")]
            subject = next((item for name, item in row.items() if str(name).lower() == f"{prefix}subject".lower()), "")
            size = next((item for name, item in row.items() if str(name).lower() == f"{prefix}sizeinbytes".lower()), "")
            add(value, subject, size)
        if isinstance(value, str):
            text = value.strip()
            if text.startswith(("[", "{")) and "internetmessageid" in text.casefold():
                try:
                    walk(json.loads(text))
                except (json.JSONDecodeError, TypeError):
                    try:
                        walk(ast.literal_eval(text))
                    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
                        pass
            for message_id, subject in MESSAGE_SUBJECT_RE.findall(text):
                add(message_id, subject)

    fallback_subject = next((str(row.get(key, "")).strip() for key in ("Item.Subject", "Subject") if row.get(key)), "")
    paired_ids = {message_id for message_id, _ in details}
    raw_ids = str(row.get("InternetMessageIDs", "")).split(";")
    fallback_size = next((str(row.get(key, "")).strip() for key in ("Item.SizeInBytes", "SizeInBytes") if row.get(key)), "")
    for message_id in raw_ids:
        clean_id = format_message_id(message_id)
        if clean_id and clean_id not in paired_ids:
            single = len(raw_ids) == 1
            add(clean_id, fallback_subject if single else "", fallback_size if single else "")
    return [(message_id, subject, size) for (message_id, subject), size in details.items()]


def extract_message_subject_pairs(row: Dict[str, Any]) -> List[Tuple[str, str]]:
    return [(message_id, subject) for message_id, subject, _ in extract_message_subject_details(row)]


def message_subject_export_rows(rows: List[Dict[str, Any]], include_size: bool = False) -> List[Dict[str, str]]:
    unique: Dict[str, Dict[str, str]] = {}
    for row in rows:
        sizes = str(row.get("MessageSubject.SizeInBytes", "") or "").split("; ")
        for index, line in enumerate(str(row.get("MessageSubject.Pairs", "") or "").splitlines()):
            message_id, separator, subject = line.partition(" → ")
            if not separator:
                continue
            message_id = format_message_id(message_id)
            if not message_id or "@" not in message_id:
                continue
            subject = subject.strip()
            if subject == "(no subject)":
                subject = ""
            size = sizes[index].strip() if index < len(sizes) else ""
            if size == "(not recorded)":
                size = ""
            key = message_id.casefold()
            if key not in unique:
                unique[key] = {"InternetMessageId": message_id, "Subject": subject}
                if include_size:
                    unique[key]["SizeInBytes"] = size
            elif not unique[key]["Subject"] and subject:
                unique[key]["Subject"] = subject
            if include_size and not unique[key].get("SizeInBytes") and size:
                unique[key]["SizeInBytes"] = size
    return list(unique.values())


def add_inbox_rule_review(row: Dict[str, Any]) -> Dict[str, Any]:
    if "inboxrule" not in str(row.get("Operation", "")).lower():
        return row
    parameters = []
    for key, value in row.items():
        if key.lower() in ("parameters", "auditdata.parameters"):
            try:
                parameters = json.loads(value) if isinstance(value, str) else value
            except (json.JSONDecodeError, TypeError):
                parameters = []
            break
    values: Dict[str, Any] = {}
    if isinstance(parameters, list):
        for item in parameters:
            if isinstance(item, dict) and item.get("Name"):
                values[str(item["Name"])] = json_safe(item.get("Value", ""))
    for source_name, display_name in INBOX_RULE_FIELDS.items():
        value = next((v for k, v in values.items() if k.lower() == source_name), "")
        if value == "":
            value = next((v for k, v in row.items() if k.lower() == source_name), "")
        if value != "":
            row[f"InboxRule.{display_name}"] = value
    noise = {"force", "alwaysdeleteoutlookrulesblob"}
    details = [f"{key}={value}" for key, value in values.items() if key.lower() not in noise and str(value) != ""]
    if details:
        row["InboxRule.Details"] = "; ".join(details)
    return row


def _named_properties(row: Dict[str, Any], names: Tuple[str, ...]) -> Dict[str, Any]:
    for key, value in row.items():
        if key.lower() in names:
            try:
                items = json.loads(value) if isinstance(value, str) else value
            except (json.JSONDecodeError, TypeError):
                return {}
            if isinstance(items, list):
                return {str(item.get("Name", "")): json_safe(item.get("Value", ""))
                        for item in items if isinstance(item, dict) and item.get("Name")}
    return {}


def _is_login_operation(operation: Any) -> bool:
    text = str(operation or "").lower()
    return any(marker in text for marker in ("login", "logon", "loggedin", "loggedout"))


def add_login_review(row: Dict[str, Any]) -> Dict[str, Any]:
    if not _is_login_operation(row.get("Operation")):
        return row
    device = _named_properties(row, ("deviceproperties", "auditdata.deviceproperties"))
    extended = _named_properties(row, ("extendedproperties", "auditdata.extendedproperties"))
    for source, display in LOGIN_DEVICE_FIELDS.items():
        value = next((v for k, v in device.items() if k.lower() == source), "")
        if value != "": row[f"Login.{display}"] = value
    for source, display in LOGIN_EXTENDED_FIELDS.items():
        value = next((v for k, v in extended.items() if k.lower() == source), "")
        if value != "": row[f"Login.{display}"] = value
    return row


def _populated_field(row: Dict[str, Any], *names: str) -> str:
    wanted = {name.casefold() for name in names}
    for key, value in row.items():
        if str(key).casefold() in wanted and str(value or "").strip():
            return str(value).strip()
    return ""


def _actor_user_agent(value: Any) -> str:
    text = str(value or "").strip()
    match = re.search(r"(?:^|;)\s*UserAgent\s*(?:=|:|-)\s*(.+?)\s*$", text, re.I)
    return match.group(1).strip() if match else ""


def add_mail_review(row: Dict[str, Any]) -> Dict[str, Any]:
    if not matches_event_category(row, "email_access"):
        return row
    actor = _populated_field(row, "ActorInfoString", "AuditData.ActorInfoString")
    reported_agent = _populated_field(row, "UserAgent", "AuditData.UserAgent")
    client = _populated_field(row, "ClientInfoString", "AuditData.ClientInfoString")
    if actor:
        row["Mail.ActorInfoString"] = actor
    user_agent = _actor_user_agent(actor) or actor or reported_agent
    if user_agent:
        row["Mail.UserAgent"] = user_agent
    if client:
        row["Mail.ClientInfoString"] = client
    return row


def parse_rows(source_rows: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    parsed, errors = [], 0
    for index, source in enumerate(source_rows, 1):
        clean = {str(k): json_safe(v) for k, v in source.items()}
        audit_raw = str(clean.get("AuditData", "") or "")
        expanded: Dict[str, Any] = {}
        parse_error = ""
        if audit_raw.strip():
            try:
                obj = json.loads(audit_raw)
                if isinstance(obj, dict):
                    expanded = flatten(obj)
                else:
                    parse_error = "AuditData JSON is not an object"
            except (json.JSONDecodeError, TypeError) as exc:
                parse_error = str(exc)
        row = {k: v for k, v in clean.items() if k != "AuditData"}
        for key, value in expanded.items():
            target = key if key not in row else f"AuditData.{key}"
            row[target] = value
        row["_Row"] = index
        if parse_error:
            errors += 1
            row["_ParseError"] = parse_error
            row["_RawAuditData"] = audit_raw
        ids = extract_message_ids(row, audit_raw)
        row["InternetMessageIDs"] = "; ".join(ids)
        parsed.append(row)
    return parsed, errors


def parse_message_trace_rows(source_rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for index, source in enumerate(source_rows, 1):
        clean = {str(key).strip(): json_safe(value) for key, value in source.items() if str(key).strip()}
        if not any(str(value).strip() for value in clean.values() if value is not None):
            continue
        row = dict(clean)
        for key, value in clean.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
            canonical = MESSAGE_TRACE_HEADERS.get(normalized)
            if canonical and canonical not in row and str(value).strip():
                row[canonical] = value
        row["_Row"] = index
        rows.append(row)
    return rows


def message_trace_ip_columns(columns: Iterable[str]) -> List[str]:
    preferred = ["OriginalClientIP", "ClientIP", "FromIP", "ToIP", "IPAddress"]
    available = list(columns)
    selected = [column for column in preferred if column in available]
    for column in available:
        compact = re.sub(r"[^a-z0-9]", "", column.casefold())
        if "_ipapi_" not in column.casefold() and (compact.endswith("ip") or compact.endswith("ipaddress")) and column not in selected:
            selected.append(column)
    return selected


def normalize_ip(value: Any) -> Optional[str]:
    text = str(value or "").strip().strip("'")
    if not text:
        return None
    candidate = text
    if text.startswith("[") and "]" in text:
        candidate = text[1:text.index("]")]
    elif text.count(":") == 1:
        host, separator, port = text.rpartition(":")
        if separator and port.isdigit():
            candidate = host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def ip_columns(columns: Iterable[str]) -> List[str]:
    preferred = set(sum((v for k, v in ALIASES.items() if k in ("ip", "clientip")), []))
    return [c for c in columns if c in preferred or c.lower().endswith("ipaddress")]


def classify_ip(ip: str) -> str:
    obj = ipaddress.ip_address(ip)
    if obj.is_loopback: return "Loopback"
    if obj.is_link_local: return "Link-local"
    if obj.is_private: return "Private"
    if obj.is_multicast: return "Multicast"
    if obj.is_reserved: return "Reserved"
    return "Public"


def _values_for_field(row: Dict[str, Any], field: str) -> List[str]:
    names = ALIASES.get(field.lower())
    if names:
        values = [row.get(name, "") for name in names]
    else:
        exact = [k for k in row if k.lower() == field.lower()]
        partial = [k for k in row if field.lower() in k.lower()]
        values = [row.get(k, "") for k in (exact or partial)]
    return [str(v) for v in values]


def _comparison_value(value: Any) -> Tuple[str, Any]:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
        parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return "datetime", parsed.timestamp()
    except ValueError:
        pass
    try:
        return "number", float(text)
    except ValueError:
        return "text", text.casefold()


def _compare_query_values(left: str, right: str, operator: str) -> bool:
    left_type, left_value = _comparison_value(left)
    right_type, right_value = _comparison_value(right)
    if left_type != right_type:
        left_value, right_value = str(left).casefold(), str(right).casefold()
    if operator == ">": return left_value > right_value
    if operator == ">=": return left_value >= right_value
    if operator == "<": return left_value < right_value
    if operator == "<=": return left_value <= right_value
    return False


def compile_query(text: str):
    try:
        lexer = shlex.shlex(text or "", posix=True, punctuation_chars="()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        raw_tokens = list(lexer)
        tokens = [part for token in raw_tokens for part in (list(token) if token and set(token) <= {"(", ")"} else [token])]
    except ValueError as exc:
        raise ValueError(f"Invalid query: {exc}") from exc

    def parse_term(index: int):
        token = tokens[index]
        negative = token.startswith("-") and len(token) > 1
        token = token[1:] if negative else token
        if ":" in token:
            field, value = token.split(":", 1)
            next_is_field = index + 1 < len(tokens) and re.match(r"^-?[A-Za-z_][A-Za-z0-9_.]*:", tokens[index + 1])
            next_is_boundary = index + 1 < len(tokens) and (tokens[index + 1].upper() in ("OR", "||", "AND", "&&") or tokens[index + 1] in ("(", ")"))
            if not value and index + 1 < len(tokens) and not next_is_field and not next_is_boundary:
                index += 1
                value = tokens[index]
        else:
            field, value = "", token
        operator = ""
        if field:
            operator = next((candidate for candidate in (">=", "<=", ">", "<", "=") if value.startswith(candidate)), "")
            value = value[len(operator):] if operator else value
        exact = operator == "="
        if not value and not exact:
            raise ValueError(f"Query field '{field}' is missing a value")
        wildcard = re.compile(re.escape(value).replace(r"\*", ".*"), re.I) if "*" in value and not operator else None
        return (negative, field.strip(), value, wildcard, operator), index + 1

    position = 0

    def parse_factor():
        nonlocal position
        if position >= len(tokens):
            raise ValueError("Invalid query: expected an expression")
        token = tokens[position]
        if token == "(":
            position += 1
            if position < len(tokens) and tokens[position] == ")":
                raise ValueError("Invalid query: parentheses cannot be empty")
            node = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("Invalid query: missing closing parenthesis")
            position += 1
            return node
        if token == ")":
            raise ValueError("Invalid query: unexpected closing parenthesis")
        if token.upper() in ("OR", "||", "AND", "&&"):
            raise ValueError(f"Invalid query: {token.upper()} must separate complete expressions")
        term, position = parse_term(position)
        return ("term", term)

    def parse_and():
        nonlocal position
        nodes = [parse_factor()]
        while position < len(tokens) and tokens[position] != ")" and tokens[position].upper() not in ("OR", "||"):
            if tokens[position].upper() in ("AND", "&&"):
                connector = tokens[position].upper()
                position += 1
                if position >= len(tokens) or tokens[position] == ")" or tokens[position].upper() in ("OR", "||", "AND", "&&"):
                    raise ValueError(f"Invalid query: {connector} must separate complete expressions")
            nodes.append(parse_factor())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def parse_or():
        nonlocal position
        nodes = [parse_and()]
        while position < len(tokens) and tokens[position].upper() in ("OR", "||"):
            connector = tokens[position].upper()
            position += 1
            if position >= len(tokens) or tokens[position] == ")" or tokens[position].upper() in ("OR", "||", "AND", "&&"):
                raise ValueError(f"Invalid query: {connector} must separate complete expressions")
            nodes.append(parse_and())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    tree = parse_or() if tokens else None
    if position != len(tokens):
        if tokens[position] == ")":
            raise ValueError("Invalid query: unexpected closing parenthesis")
        raise ValueError(f"Invalid query near '{tokens[position]}'")

    def term_matches(row: Dict[str, Any], term) -> bool:
        negative, field, needle, wildcard, operator = term
        values = _values_for_field(row, field) if field else [str(v) for v in row.values()]
        if field and operator == "=" and needle == "" and not values:
            values = [""]  # Derived fields with no value are intentionally omitted from the row.
        if operator in (">", ">=", "<", "<="):
            hit = any(_compare_query_values(value, needle, operator) for value in values if value.strip())
        else:
            folded_needle = needle.casefold()
            hit = any(value.casefold() == folded_needle if operator == "=" else bool(wildcard.fullmatch(value)) if wildcard else folded_needle in value.casefold() for value in values)
        return hit != negative

    def matches(row: Dict[str, Any]) -> bool:
        def evaluate(node) -> bool:
            if node[0] == "term": return term_matches(row, node[1])
            if node[0] == "and": return all(evaluate(child) for child in node[1])
            return any(evaluate(child) for child in node[1])
        return True if tree is None else evaluate(tree)
    return matches


ACTIVITY_CATEGORY_OPERATIONS = {
    "logon": frozenset({"userloggedin", "userloginfailed"}),
    "inbox_rules": frozenset({"newinboxrule", "setinboxrule", "updateinboxrule", "updateinboxrules"}),
    "transport_rules": frozenset({"newtransportrule", "settransportrule", "enabletransportrule", "removetransportrule"}),
    "mailbox_permissions": frozenset({"addmailboxpermission", "removemailboxpermission"}),
    "email_access": frozenset({"mailitemsaccessed", "softdelete", "create", "update", "move", "movetodeleteditems", "harddelete", "send", "sendas"}),
    "file_access": frozenset({
        "fileaccessed", "fileaccessedextended", "filepreviewed", "filecopied", "filedeleted",
        "filedownloaded", "filemodified", "filemodifiedextended", "searchqueryperformed",
        "foldercopied", "foldercreated", "foldermoved", "folderrename", "folderrenamed",
        "folderrestored", "foldermodified", "folderdeletedfirststagerecyclebin",
        "folderdeletedsecondstagerecyclebin",
    }),
}
ACTIVITY_CATEGORIES = (*ACTIVITY_CATEGORY_OPERATIONS.keys(), "other")
_CATEGORIZED_ACTIVITY_OPERATIONS = frozenset().union(*ACTIVITY_CATEGORY_OPERATIONS.values())


def _normalized_operation(row: Dict[str, Any]) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(row.get("Operation", "")).casefold())


def matches_event_category(row: Dict[str, Any], category: str) -> bool:
    operation = str(row.get("Operation", "")).lower()
    workload = str(row.get("Workload", "")).lower()
    record_type = str(row.get("RecordType", "")).lower()
    category = (category or "").lower()
    if not category:
        return True
    normalized_operation = _normalized_operation(row)
    if category in ACTIVITY_CATEGORY_OPERATIONS:
        return normalized_operation in ACTIVITY_CATEGORY_OPERATIONS[category]
    if category == "other":
        return normalized_operation not in _CATEGORIZED_ACTIVITY_OPERATIONS
    if category == "inbox_rules":
        return "inboxrule" in operation
    if category == "logins":
        return _is_login_operation(operation)
    if category == "teams":
        return "teams" in workload or "teams" in record_type or "team" in operation and workload not in ("exchange", "")
    if category == "files":
        return workload in ("sharepoint", "onedrive", "onedriveforbusiness") or any(
            word in operation for word in ("fileaccessed", "filedownloaded", "fileuploaded", "filedeleted",
                                            "filemodified", "filecopied", "filemoved", "foldercreated",
                                            "sharinginvitation", "anonymouslink", "securelink"))
    if category == "mail":
        return workload == "exchange" and any(word in operation for word in (
            "mailitemsaccessed", "message", "send", "mailbox", "movetodeleteditems", "softdelete",
            "harddelete", "updateinboxrules", "inboxrule"))
    return True


def _event_value(row: Dict[str, Any], *names: str, limit: int = 320,
                 lookup: Optional[Dict[str, Any]] = None) -> str:
    lookup = lookup if lookup is not None else {str(key).casefold(): value for key, value in row.items()}
    for name in names:
        value = lookup.get(name.casefold(), "")
        text = "" if value is None else re.sub(r"\s+", " ", str(value)).strip()
        if text:
            return text if len(text) <= limit else f"{text[:limit - 1]}…"
    return ""


def _event_ip_context(row: Dict[str, Any], lookup: Dict[str, Any]) -> Tuple[str, List[str]]:
    value = lambda *names: _event_value(row, *names, lookup=lookup)
    sources = ["ClientIP", "ClientIPAddress", "ActorIpAddress", "OriginalClientIP", "FromIP", "ToIP", "IPAddress", "OriginatingServer"]
    candidates = [(source, normalize_ip(value(source))) for source in sources]
    candidates = [(source, ip) for source, ip in candidates if ip]
    if not candidates:
        return "", []
    source, ip = next(
        ((source, ip) for source, ip in candidates if any(
            value(f"{source}_IPAPI_{suffix}")
            for suffix in ("Country", "Region", "City", "ISP", "Proxy_VPN_TOR", "Hosting")
        )),
        candidates[0],
    )
    city = value(f"{source}_IPAPI_City")
    region = value(f"{source}_IPAPI_Region")
    country = value(f"{source}_IPAPI_Country")
    location = ", ".join(value for value in (country, region, city) if value)
    context = []
    if location: context.append(f"geo-location {location}")
    isp = value(f"{source}_IPAPI_ISP")
    if isp: context.append(f"ISP {isp}")
    vpn = value(f"{source}_IPAPI_Proxy_VPN_TOR")
    if vpn.casefold() in ("true", "1", "yes"): context.append("VPN/Proxy/TOR")
    hosting = value(f"{source}_IPAPI_Hosting")
    if hosting.casefold() in ("true", "1", "yes"): context.append("Hosting")
    return ip, context


def build_event_summary(row: Dict[str, Any]) -> str:
    lookup = {str(key).casefold(): value for key, value in row.items()}
    value = lambda *names: _event_value(row, *names, lookup=lookup)
    operation = value("Operation") or "Audit event"
    user = value("UserId", "MailboxOwnerUPN", "Actor.UserId", "Sender", "UserKey")
    workload = value("Workload")
    result = value("ResultStatus", "Result", "Login.ResultStatusDetail", "LogonError")
    ip, ip_context = _event_ip_context(row, lookup)
    clauses: List[str] = []

    if user: clauses.append(user)
    if ip: clauses.append(f"from IP {ip}")
    clauses.extend(ip_context)

    is_login = matches_event_category(row, "logins")
    if is_login:
        pass  # For login tracker narratives, actor and IP intelligence are sufficient.
    elif matches_event_category(row, "inbox_rules"):
        rule_name = value("InboxRule.Name")
        details = value("InboxRule.Details")
        if rule_name: clauses.append(f"rule {rule_name}")
        if details: clauses.append(f"actions {details}")
    elif matches_event_category(row, "teams"):
        team = value("TeamName")
        channel = value("ChannelName")
        chat = value("ChatThreadId")
        meeting = value("MeetingId")
        if team: clauses.append(f"team {team}")
        if channel: clauses.append(f"channel {channel}")
        if chat: clauses.append(f"chat {chat}")
        if meeting: clauses.append(f"meeting {meeting}")
    elif matches_event_category(row, "files"):
        source = value("SourceFileName", "ItemName", "ObjectId")
        destination = value("DestinationFileName")
        folder = value("FolderPathName", "SourceRelativeUrl")
        site = value("SiteUrl")
        if source: clauses.append(f"item {source}")
        if destination and destination != source: clauses.append(f"destination {destination}")
        if folder: clauses.append(f"path {folder}")
        if site: clauses.append(f"site {site}")
        external = value("ExternalAccess")
        if external: clauses.append(f"external access {external}")
    elif matches_event_category(row, "mail"):
        mailbox = value("MailboxOwnerUPN")
        subject = value("MessageSubject.Subjects", "Item.Subject", "Subject")
        message_id = value("MessageSubject.InternetMessageIDs", "InternetMessageIDs", "InternetMessageId", "Item.InternetMessageId")
        folder = value("FolderPathName", "ItemName")
        if mailbox and mailbox.casefold() != user.casefold(): clauses.append(f"mailbox {mailbox}")
        if subject: clauses.append(f"subject {subject}")
        if message_id: clauses.append(f"message ID {message_id}")
        if folder: clauses.append(f"folder/item {folder}")
    else:
        object_id = value("ObjectId", "ItemName")
        if object_id: clauses.append(f"object {object_id}")

    if not is_login and workload: clauses.append(f"workload {workload}")
    if not is_login and result: clauses.append(f"result {result}")
    description = "; ".join(clauses) if clauses else "No additional populated context"
    return f"{operation}: {description}."


def build_message_trace_event_summary(row: Dict[str, Any]) -> str:
    lookup = {str(key).casefold(): value for key, value in row.items()}
    value = lambda *names: _event_value(row, *names, lookup=lookup)
    subject = value("message_subject", "Subject", "MessageSubject", "Message Subject")
    sender = value("SenderAddress", "Sender")
    recipient = value("RecipientAddress", "Recipient")
    return f"Subject: {subject}; Sender: {sender}; Recipient: {recipient}"


def row_columns(rows: List[Dict[str, Any]]) -> List[str]:
    def has_value(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, set, dict)):
            return bool(value)
        return True  # False and 0 are meaningful investigation values.

    seen = set()
    columns = []
    priority = [
        "_Row", "CreationTime", "Operation", "Event", "Review.Tag", "SuspiciousLogin.Flag", "SuspiciousLogin.Risk",
        "SuspiciousLogin.Score", "SuspiciousLogin.IP", "SuspiciousLogin.Location", "SuspiciousLogin.ISP",
        "SuspiciousLogin.Proxy_VPN_TOR", "SuspiciousLogin.Hosting", "SuspiciousLogin.IsCompliant",
        "SuspiciousLogin.IsCompliantAndManaged", "SuspiciousLogin.Reasons",
        "Travel.Flag", "Travel.Risk", "Travel.Score",
        "Travel.ElapsedHours", "Travel.PreviousTime", "Travel.PreviousIP", "Travel.PreviousISP",
        "Travel.PreviousLocation", "Travel.CurrentISP", "Travel.CurrentLocation",
        "Travel.HostingOrVPN", "Travel.DeviceRisk", "Travel.Reasons",
        "Login.SessionId", "Login.IsCompliant",
        "Login.IsManaged", "Login.IsCompliantAndManaged", "Login.OS", "Login.BrowserType",
        "Login.DeviceId", "Login.DeviceName", "Login.TrustType", "Login.ResultStatusDetail",
        "Login.UserAuthenticationMethod", "Login.RequestType", "Login.UserAgent",
        "InboxRule.Name", "InboxRule.Details",
        "InboxRule.From", "InboxRule.MoveToFolder", "InboxRule.ForwardTo", "InboxRule.RedirectTo",
        "InboxRule.ForwardAsAttachmentTo", "InboxRule.DeleteMessage", "InboxRule.StopProcessingRules",
        "Mail.ActorInfoString", "Mail.UserAgent", "Mail.ClientInfoString",
        "UserId", "UserKey", "UserType", "ClientIP",
        "ClientIPAddress", "Workload", "RecordType", "ResultStatus", "ObjectId", "ItemName",
        "FolderPathName", "MailboxOwnerUPN", "SiteUrl", "SourceFileName", "DestinationFileName",
        "ExternalAccess", "LogonType", "ActorIpAddress", "InternetMessageId", "InternetMessageIDs",
    ]
    all_keys = {key for row in rows for key, value in row.items() if has_value(value)}
    for key in priority + sorted(all_keys):
        if key in all_keys and key not in seen:
            seen.add(key); columns.append(key)
    return columns


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    operations = Counter(str(r.get("Operation", "Unknown") or "Unknown") for r in rows)
    columns = row_columns(rows)
    metrics = summarize_metrics(rows, columns)
    return {
        **metrics,
        "operations": [{"name": k, "count": v} for k, v in operations.most_common(12)],
        "categories": {name: sum(1 for row in rows if matches_event_category(row, name))
                       for name in ACTIVITY_CATEGORIES},
    }


def summarize_metrics(rows: List[Dict[str, Any]], columns: Optional[List[str]] = None) -> Dict[str, Any]:
    columns = columns if columns is not None else row_columns(rows)
    users = set()
    for row in rows:
        identity = next((str(row.get(field)).strip() for field in ALIASES["user"] if str(row.get(field) or "").strip()), "")
        if identity:
            users.add(identity.casefold())
    message_ids = {x.strip() for row in rows for x in str(row.get("InternetMessageIDs", "")).split(";") if x.strip()}
    ips = set()
    candidate_ip_columns = ip_columns(columns)
    for row in rows:
        for col in candidate_ip_columns:
            ip = normalize_ip(row.get(col))
            if ip: ips.add(ip)
    return {
        "rows": len(rows), "columns": len(columns), "users": len(users),
        "ips": len(ips), "messageIds": len(message_ids),
        "tagged": sum(1 for row in rows if row.get("Review.Tag")),
    }


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "1", "yes")


def _falsey(value: Any) -> bool:
    return value is False or str(value).strip().lower() in ("false", "0", "no")


def _audit_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text: return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def analyze_impossible_travel(rows: List[Dict[str, Any]], enrichment: Dict[str, Dict[str, Any]],
                              enriched_ip_columns: List[str], options: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    if not enrichment or not enriched_ip_columns:
        raise ValueError("IP enrichment is required before running Impossible Travel")
    if options is not None and not isinstance(options, dict):
        raise ValueError("Impossible Travel options must be an object")
    options = options or {}
    use_country_change = options.get("useCountryChange", True) is True
    use_region_change = options.get("useRegionChange", True) is True
    use_elevated_window = options.get("useElevatedWindow", True) is True
    country_hours = max(0.01, min(float(options.get("countryHours", 12)), 720))
    region_hours = max(0.01, min(float(options.get("regionHours", 3)), 720))
    elevated_hours = max(0.01, min(float(options.get("elevatedHours", 24)), 720))
    use_hosting = options.get("useHosting", True) is True
    use_proxy = options.get("useProxy", True) is True
    use_device_risk = options.get("useDeviceRisk", True) is True
    if not (use_country_change or use_region_change or use_elevated_window):
        raise ValueError("Select at least one Impossible Travel rule")
    if use_elevated_window and not (use_hosting or use_proxy or use_device_risk):
        raise ValueError("Select at least one elevated-risk signal")
    candidates: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    preferred_ip = "ClientIP" if "ClientIP" in enriched_ip_columns else enriched_ip_columns[0]
    for row in rows:
        if "userloggedin" not in str(row.get("Operation", "")).lower():
            continue
        timestamp = _audit_time(row.get("CreationTime"))
        user = str(row.get("UserId") or row.get("UserKey") or "").strip().lower()
        ip = normalize_ip(row.get(preferred_ip))
        intel = enrichment.get(ip or "", {})
        if not timestamp or not user or not ip or intel.get("Lookup_Status") != "Success":
            continue
        if not intel.get("Country") and not intel.get("Region"):
            continue
        candidates[user].append({"row": row, "time": timestamp, "ip": ip, "intel": intel})

    findings: Dict[str, Dict[str, Any]] = {}
    for events in candidates.values():
        events.sort(key=lambda item: item["time"])
        for previous, current in zip(events, events[1:]):
            elapsed = (current["time"] - previous["time"]).total_seconds() / 3600
            if elapsed < 0: continue
            before, after = previous["intel"], current["intel"]
            old_country, new_country = str(before.get("Country", "")), str(after.get("Country", ""))
            old_region, new_region = str(before.get("Region", "")), str(after.get("Region", ""))
            country_changed = bool(old_country and new_country and old_country.casefold() != new_country.casefold())
            region_changed = bool(old_region and new_region and old_region.casefold() != new_region.casefold())
            hosting = use_hosting and any(_truthy(item.get("Hosting")) for item in (before, after))
            proxy = use_proxy and any(_truthy(item.get("Proxy_VPN_TOR")) for item in (before, after))
            infrastructure = hosting or proxy
            device_risk = use_device_risk and any(_falsey(item["row"].get("Login.IsCompliantAndManaged")) or
                                                   _falsey(item["row"].get("Login.IsCompliant")) or
                                                   _falsey(item["row"].get("Login.IsManaged")) for item in (previous, current))
            country_candidate = use_country_change and country_changed and elapsed <= country_hours
            region_candidate = use_region_change and region_changed and elapsed <= region_hours
            travel_candidate = country_candidate or region_candidate
            elevated_candidate = use_elevated_window and country_changed and elapsed <= elevated_hours and (infrastructure or device_risk)
            if not (travel_candidate or elevated_candidate):
                continue
            score, reasons = 0, []
            if country_candidate or elevated_candidate:
                score += 4 if elapsed <= 4 else 3 if elapsed <= country_hours else 1
                reasons.append(f"Country changed within {elapsed:.2f}h")
            elif region_candidate:
                score += 2; reasons.append(f"Region changed within {elapsed:.2f}h")
            if hosting:
                score += 2; reasons.append("Hosting provider IP")
            if proxy:
                score += 2; reasons.append("Proxy/VPN/TOR indicator")
            if device_risk:
                score += 2; reasons.append("Device not compliant and managed")
            row_key = str(current["row"].get("_Row", ""))
            findings[row_key] = {
                "Flag": True, "Risk": "High" if score >= 6 else "Medium" if score >= 3 else "Low",
                "Score": score, "ElapsedHours": round(elapsed, 2), "PreviousTime": previous["time"].isoformat(),
                "PreviousIP": previous["ip"], "PreviousISP": before.get("ISP", ""),
                "PreviousLocation": ", ".join(x for x in (old_region, old_country) if x),
                "CurrentISP": after.get("ISP", ""), "CurrentLocation": ", ".join(x for x in (new_region, new_country) if x),
                "HostingOrVPN": infrastructure, "DeviceRisk": device_risk, "Reasons": "; ".join(reasons),
            }
    return findings


def analyze_suspicious_logins(rows: List[Dict[str, Any]], enrichment: Dict[str, Dict[str, Any]],
                              enriched_ip_columns: List[str], options: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    if not enrichment or not enriched_ip_columns:
        raise ValueError("IP enrichment is required before hunting suspicious logins")
    if options is not None and not isinstance(options, dict):
        raise ValueError("Suspicious Login options must be an object")
    options = options or {}
    use_country = options.get("useCountry", True) is True
    trusted_values = options.get("trustedCountries", ["United States"])
    if isinstance(trusted_values, str):
        trusted_values = re.split(r"[\n,]+", trusted_values)
    country_aliases = {"us": "unitedstates", "usa": "unitedstates", "unitedstatesofamerica": "unitedstates"}
    country_key = lambda value: country_aliases.get(re.sub(r"[^a-z]", "", str(value or "").casefold()), re.sub(r"[^a-z]", "", str(value or "").casefold()))
    trusted_countries = {country_key(value) for value in trusted_values if str(value).strip()}
    use_proxy = options.get("useProxy", True) is True
    use_hosting = options.get("useHosting", True) is True
    require_device_risk = options.get("requireDeviceRisk", True) is True
    missing_device_risky = options.get("missingDeviceRisky", True) is True
    if use_country and not trusted_countries:
        raise ValueError("Enter at least one trusted country or disable the country rule")
    if not (use_country or use_proxy or use_hosting):
        raise ValueError("Select at least one Suspicious Login rule")
    preferred_ip = "ClientIP" if "ClientIP" in enriched_ip_columns else enriched_ip_columns[0]
    findings: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not _is_login_operation(row.get("Operation")):
            continue
        ip = normalize_ip(row.get(preferred_ip))
        intel = enrichment.get(ip or "", {})
        if not ip or intel.get("Lookup_Status") != "Success":
            continue
        proxy = _truthy(intel.get("Proxy_VPN_TOR"))
        hosting = _truthy(intel.get("Hosting"))
        country = str(intel.get("Country", "")).strip()
        outside_trusted_countries = use_country and bool(country) and country_key(country) not in trusted_countries
        compliant = row.get("Login.IsCompliant", "")
        compliant_managed = row.get("Login.IsCompliantAndManaged", "")
        compliant_bad = (_falsey(compliant) or (missing_device_risky and str(compliant).strip() == ""))
        combined_bad = (_falsey(compliant_managed) or (missing_device_risky and str(compliant_managed).strip() == ""))
        device_risk = compliant_bad and combined_bad
        infrastructure = (use_proxy and proxy) or (use_hosting and hosting)
        infrastructure_candidate = infrastructure and (device_risk or not require_device_risk)
        if not (outside_trusted_countries or infrastructure_candidate):
            continue
        score, reasons = 0, []
        if outside_trusted_countries:
            score += 4; reasons.append(f"Login country outside trusted countries ({country})")
        if use_proxy and proxy: score += 3; reasons.append("Proxy/VPN/TOR indicator")
        if use_hosting and hosting: score += 3; reasons.append("Hosting provider IP")
        if require_device_risk and infrastructure:
            if str(compliant).strip() == "": score += 1; reasons.append("IsCompliant missing")
            elif _falsey(compliant): score += 2; reasons.append("IsCompliant=False")
            if str(compliant_managed).strip() == "": score += 1; reasons.append("IsCompliantAndManaged missing")
            elif _falsey(compliant_managed): score += 2; reasons.append("IsCompliantAndManaged=False")
        row_key = str(row.get("_Row", ""))
        findings[row_key] = {
            "Flag": True, "Risk": "High" if score >= 7 else "Medium", "Score": score, "IP": ip,
            "Location": ", ".join(str(intel.get(key, "")) for key in ("City", "Region", "Country") if intel.get(key)),
            "ISP": intel.get("ISP", ""), "Proxy_VPN_TOR": proxy, "Hosting": hosting, "IsCompliant": compliant,
            "IsCompliantAndManaged": compliant_managed, "Reasons": "; ".join(reasons),
        }
    return findings


def normalize_domain(value: Any) -> Optional[str]:
    text = str(value or "").strip().strip(".").casefold()
    if not text or len(text) > 253:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return None
    return text


def email_domains(value: Any) -> List[str]:
    domains = []
    for match in EMAIL_DOMAIN_RE.finditer(str(value or "")):
        domain = normalize_domain(match.group(1))
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def _rdap_vcard_name(entity: Dict[str, Any]) -> str:
    try:
        entries = entity.get("vcardArray", [None, []])[1]
        for preferred in ("fn", "org"):
            for entry in entries:
                if isinstance(entry, list) and len(entry) >= 4 and entry[0] == preferred:
                    value = entry[3]
                    return ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)
    except (AttributeError, IndexError, TypeError):
        pass
    return ""


def parse_rdap_domain(payload: Dict[str, Any], requested_domain: str) -> Dict[str, Any]:
    events = {}
    for event in payload.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            events[str(event["eventAction"]).casefold()] = event["eventDate"]
    registrar = ""
    for entity in payload.get("entities", []):
        if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
            registrar = _rdap_vcard_name(entity) or str(entity.get("handle", ""))
            if registrar:
                break
    nameservers = sorted({str(item.get("ldhName", "")).casefold() for item in payload.get("nameservers", []) if isinstance(item, dict) and item.get("ldhName")})
    secure_dns = payload.get("secureDNS", {}) if isinstance(payload.get("secureDNS"), dict) else {}
    return {
        "Domain": requested_domain,
        "RegisteredDomain": str(payload.get("ldhName") or payload.get("unicodeName") or requested_domain).casefold(),
        "Registrar": registrar,
        "RegistrationDate": events.get("registration", ""),
        "ExpirationDate": events.get("expiration", ""),
        "LastChangedDate": events.get("last changed", ""),
        "Status": "; ".join(str(item) for item in payload.get("status", [])),
        "NameServers": "; ".join(nameservers),
        "DNSSEC": "Signed" if secure_dns.get("delegationSigned") is True else "Unsigned" if secure_dns.get("delegationSigned") is False else "",
        "Lookup_Status": "Success", "Provider": "RDAP", "Error": "",
    }


def enrich_domains_rdap(domains: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    unique = sorted({domain for value in domains if (domain := normalize_domain(value))})
    if not unique:
        return {}
    request = urllib.request.Request(RDAP_BOOTSTRAP_URL, headers={"Accept": "application/json", "User-Agent": "M365-UAL-Investigator/2.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            bootstrap = json.load(response)
    except Exception as exc:
        return {domain: {"Domain": domain, "Lookup_Status": "Failed", "Provider": "RDAP", "Error": f"RDAP discovery failed: {str(exc)[:220]}"} for domain in unique}
    services = {}
    for tlds, urls in bootstrap.get("services", []):
        for tld in tlds:
            services[str(tld).casefold()] = [str(url) for url in urls]
    results = {}
    for submitted in unique:
        bases = services.get(submitted.rsplit(".", 1)[-1], [])
        if not bases:
            results[submitted] = {"Domain": submitted, "Lookup_Status": "Failed", "Provider": "RDAP", "Error": "No authoritative RDAP service found for this TLD"}
            continue
        last_error = "Domain was not found"
        labels = submitted.split(".")
        candidates = [".".join(labels[index:]) for index in range(max(1, len(labels) - 1))]
        found = None
        for candidate in candidates:
            for base in bases:
                url = base.rstrip("/") + "/domain/" + urllib.parse.quote(candidate, safe=".-")
                lookup = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "M365-UAL-Investigator/2.0"})
                try:
                    with urllib.request.urlopen(lookup, timeout=20) as response:
                        payload = json.load(response)
                    if isinstance(payload, dict):
                        found = parse_rdap_domain(payload, submitted)
                        break
                except urllib.error.HTTPError as exc:
                    last_error = f"HTTP {exc.code}"
                    if exc.code not in (400, 404):
                        break
                except Exception as exc:
                    last_error = str(exc)[:220]
                    break
            if found:
                break
        results[submitted] = found or {"Domain": submitted, "Lookup_Status": "Failed", "Provider": "RDAP", "Error": last_error}
    return results


def hunt_suspicious_message_trace(rows: List[Dict[str, Any]], domain_enrichment: Dict[str, Dict[str, Any]],
                                  domain_columns: List[str], use_domain_age: bool = True,
                                  max_age_days: int = 365, registered_after: str = "",
                                  registered_before: str = "", keywords: Optional[List[str]] = None,
                                  service_domains: Optional[List[str]] = None,
                                  now: Optional[datetime] = None) -> Dict[str, Any]:
    terms = []
    for value in keywords or []:
        term = str(value).strip()
        if term and term.casefold() not in {item.casefold() for item in terms}:
            terms.append(term)
    configured_services = []
    for value in service_domains or []:
        domain = str(value).strip().casefold().removeprefix("*.").strip(".")
        if "://" in domain:
            domain = urllib.parse.urlparse(domain).hostname or ""
        domain = domain.split("/")[0].strip(".")
        if domain and domain not in configured_services:
            configured_services.append(domain)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    after = _audit_time(registered_after)
    before = _audit_time(registered_before)
    if registered_before and len(str(registered_before).strip()) == 10 and before:
        before += timedelta(days=1)
    findings, domain_hits, subject_hits, service_hits = {}, 0, 0, 0
    for row in rows:
        subject = str(row.get("Subject") or row.get("message_subject") or "")
        matched_terms = [term for term in terms if term.casefold() in subject.casefold()]
        sender_domains = []
        for column, value in row.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(column).casefold())
            if normalized in {"sender", "senderaddress", "from", "fromaddress", "mailfromaddress", "envelopesender"}:
                for domain in email_domains(value):
                    if domain not in sender_domains:
                        sender_domains.append(domain)
        matched_services = []
        for sender_domain in sender_domains:
            service = next((item for item in configured_services
                            if sender_domain == item or sender_domain.endswith("." + item)), "")
            if service:
                matched_services.append((sender_domain, service))
        matched_domains, registration_dates, ages = [], [], []
        if use_domain_age:
            domains = []
            for column in domain_columns:
                for domain in email_domains(row.get(column)):
                    if domain not in domains:
                        domains.append(domain)
            for domain in domains:
                registration = str(domain_enrichment.get(domain, {}).get("RegistrationDate", "")).strip()
                registered = _audit_time(registration)
                if not registered:
                    continue
                if after or before:
                    matches = (not after or registered >= after) and (not before or registered < before)
                else:
                    age = (now - registered).total_seconds() / 86400
                    matches = -1 <= age <= max_age_days
                if matches:
                    matched_domains.append(domain); registration_dates.append(registration)
                    ages.append(max(0, int((now - registered).total_seconds() // 86400)))
        if not matched_domains and not matched_terms and not matched_services:
            continue
        score, reasons = 0, []
        if matched_domains:
            score += 5; domain_hits += 1
            domain_details = []
            for index, domain in enumerate(matched_domains):
                registration = registration_dates[index] if index < len(registration_dates) else ""
                age = ages[index] if index < len(ages) else ""
                if after or before:
                    domain_details.append(f"{domain} registered {registration or 'within the selected date range'}")
                else:
                    domain_details.append(f"{domain} is {age} days old (registered {registration})")
            reasons.append("Newly registered domain: " + ", ".join(domain_details))
        if matched_terms:
            score += 3; subject_hits += 1
            reasons.append("Subject contains suspicious keyword" + ("s" if len(matched_terms) != 1 else "") + ": " + ", ".join(f'\"{term}\"' for term in matched_terms))
        if matched_services:
            score += 3; service_hits += 1
            reasons.append("Third-party survey/messaging service sender domain: " + ", ".join(
                domain if domain == service else f"{domain} (matches {service})"
                for domain, service in matched_services
            ))
        signal_count = sum(bool(value) for value in (matched_domains, matched_terms, matched_services))
        findings[str(row.get("_Row", ""))] = {
            "Flag": True, "Risk": "High" if signal_count >= 2 else "Medium", "Score": score,
            "NewDomains": "; ".join(matched_domains),
            "DomainAgeDays": min(ages) if ages else "",
            "DomainRegistrationDates": "; ".join(registration_dates),
            "SubjectKeywords": "; ".join(matched_terms),
            "ServiceDomains": "; ".join(domain for domain, _service in matched_services),
            "SuspiciousReason": "; ".join(reasons),
        }
    return {"findings": findings, "findingCount": len(findings), "domainHitCount": domain_hits,
            "subjectHitCount": subject_hits, "serviceHitCount": service_hits}


def _local_ip_result(ip: str) -> Dict[str, Any]:
    return {"IP_Address": ip, "IP_Class": classify_ip(ip), "Lookup_Status": "Skipped (non-public)", "Provider": "Local"}


def enrich_ips_ipapi(ips: Iterable[str], batch_size: int = 100, api_key: str = "") -> Dict[str, Dict[str, Any]]:
    api_key = str(api_key or "").strip()
    provider = "ip-api.com Pro" if api_key else "ip-api.com"
    endpoint = IP_API_PRO_BATCH_URL if api_key else IP_API_FREE_BATCH_URL
    unique = sorted(set(ips))
    results = {ip: _local_ip_result(ip) for ip in unique if not ipaddress.ip_address(ip).is_global}
    public = [ip for ip in unique if ipaddress.ip_address(ip).is_global]
    for start in range(0, len(public), min(100, max(1, batch_size))):
        batch = public[start:start + min(100, max(1, batch_size))]
        parameters = {"fields": IP_API_FIELDS}
        if api_key:
            parameters["key"] = api_key
        query = urllib.parse.urlencode(parameters)
        request = urllib.request.Request(
            endpoint + "?" + query,
            data=json.dumps(batch).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "M365-Investigator-Suite/2.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                payload = json.load(response)
                remaining = response.headers.get("X-Rl")
                ttl = response.headers.get("X-Ttl")
            if not isinstance(payload, list) or len(payload) != len(batch):
                raise ValueError("ip-api returned an unexpected batch response")
            for submitted, record in zip(batch, payload):
                if not isinstance(record, dict): record = {"status": "fail", "message": "Invalid response item"}
                mapped = {"IP_Address": submitted, "IP_Class": "Public", "Provider": provider}
                mapped.update({name: record.get(key, "") for name, key in IP_API_OUTPUT_FIELDS.items()})
                mapped["Lookup_Status"] = "Success" if record.get("status") == "success" else "Failed"
                mapped["Error"] = record.get("message", "")
                results[submitted] = mapped
            if remaining == "0" and start + len(batch) < len(public):
                time.sleep(max(0.0, float(ttl or 0)) + 0.25)
        except urllib.error.HTTPError as exc:
            message = f"HTTP {exc.code}"
            for ip in batch: results[ip] = {"IP_Address": ip, "IP_Class": "Public", "Lookup_Status": "Failed", "Error": message, "Provider": provider}
        except Exception as exc:
            message = str(exc).replace(api_key, "[redacted]")[:300] if api_key else str(exc)[:300]
            for ip in batch: results[ip] = {"IP_Address": ip, "IP_Class": "Public", "Lookup_Status": "Failed", "Error": message, "Provider": provider}
    return results
