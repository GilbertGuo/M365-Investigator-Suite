from __future__ import annotations

import base64
import csv
import io
import json
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
TOKEN_ROOT = "https://login.microsoftonline.com"
MAX_TARGETS = 5000
REPORT_FIELDS = (
    "MailboxOwnerUPN", "InternetMessageId", "Subject", "Status",
    "EmlPath", "AttachmentCount", "Error",
)


def _decode_csv(raw: bytes) -> str:
    if b"\x00" in raw[:4096]:
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return raw.decode(encoding)
            except UnicodeError:
                pass
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            pass
    raise ValueError("CSV text encoding is not supported")


def _header_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def normalize_message_id(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if not (value.startswith("<") and value.endswith(">")):
        value = f"<{value.strip('<>')}>"
    if len(value) > 998 or "\n" in value or "\r" in value:
        raise ValueError("InternetMessageId is invalid or too long")
    return value


def validate_targets(targets: list[dict]) -> list[dict]:
    cleaned, seen = [], set()
    for target in targets:
        mailbox = str(target.get("MailboxOwnerUPN", "")).strip()
        message_id = normalize_message_id(target.get("InternetMessageId", ""))
        if not mailbox and not message_id:
            continue
        if not mailbox or "@" not in mailbox or len(mailbox) > 320:
            raise ValueError(f"Invalid MailboxOwnerUPN: {mailbox or '(empty)'}")
        if not message_id:
            raise ValueError(f"InternetMessageId is required for {mailbox}")
        key = (mailbox.casefold(), message_id.casefold())
        if key not in seen:
            seen.add(key)
            cleaned.append({"MailboxOwnerUPN": mailbox, "InternetMessageId": message_id})
    if not cleaned:
        raise ValueError("Provide at least one mailbox and InternetMessageId")
    if len(cleaned) > MAX_TARGETS:
        raise ValueError(f"A collection can contain at most {MAX_TARGETS:,} unique targets")
    return cleaned


def manual_targets(mailbox: str, message_ids: str) -> list[dict]:
    values = [part.strip() for part in re.split(r"[\r\n,;]+", str(message_ids or "")) if part.strip()]
    return validate_targets([{"MailboxOwnerUPN": mailbox, "InternetMessageId": value} for value in values])


def csv_targets(raw: bytes) -> list[dict]:
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("Collection CSV exceeds the 10 MB upload limit")
    reader = csv.DictReader(io.StringIO(_decode_csv(raw)))
    headers = reader.fieldnames or []
    lookup = {_header_key(header): header for header in headers}
    mailbox_header = lookup.get("mailboxownerupn")
    message_header = lookup.get("internetmessageid") or lookup.get("internetmessageids")
    if not mailbox_header or not message_header:
        raise ValueError("CSV must contain MailboxOwnerUPN and InternetMessageId columns")
    return validate_targets([
        {"MailboxOwnerUPN": row.get(mailbox_header, ""), "InternetMessageId": row.get(message_header, "")}
        for row in reader
    ])


def _safe_name(value: str, fallback: str, limit: int = 110) -> str:
    value = re.sub(r"[\\/:*?\"<>|\x00-\x1f]+", "_", str(value or "")).strip(" ._")
    return (value[:limit] or fallback)


class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, opener=urlopen):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.opener = opener
        self.token = ""

    def _open(self, request: Request, attempts: int = 4):
        for attempt in range(attempts):
            try:
                return self.opener(request, timeout=60)
            except HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts - 1:
                    detail = exc.read().decode("utf-8", "replace")[:500]
                    raise ValueError(f"Microsoft Graph returned HTTP {exc.code}: {detail}") from None
                delay = min(8, int(exc.headers.get("Retry-After", "1") or 1))
                time.sleep(delay)
            except URLError as exc:
                raise ValueError(f"Could not reach Microsoft Graph: {exc.reason}") from None

    def authenticate(self):
        tenant = quote(self.tenant_id, safe="")
        body = urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }).encode("ascii")
        request = Request(f"{TOKEN_ROOT}/{tenant}/oauth2/v2.0/token", data=body,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self._open(request) as response:
            payload = json.loads(response.read())
        self.token = payload.get("access_token", "")
        if not self.token:
            raise ValueError("Microsoft identity platform did not return an access token")

    def get(self, url: str, *, binary: bool = False):
        request = Request(url, headers={"Authorization": f"Bearer {self.token}", "Accept": "application/octet-stream" if binary else "application/json"})
        with self._open(request) as response:
            data = response.read()
        return data if binary else json.loads(data or b"{}")

    def pages(self, url: str):
        while url:
            payload = self.get(url)
            yield from payload.get("value", [])
            url = payload.get("@odata.nextLink", "")


def collect_emails(tenant_id: str, client_id: str, client_secret: str,
                   output_folder: str, targets: list[dict], opener=urlopen) -> dict:
    tenant_id, client_id, client_secret = (str(value or "").strip() for value in (tenant_id, client_id, client_secret))
    if not tenant_id or not client_id or not client_secret:
        raise ValueError("Tenant ID, application (client) ID, and client secret value are required")
    output_text = str(output_folder or "").strip()
    if not output_text:
        raise ValueError("Choose an output folder")
    output = Path(output_text).expanduser()
    if not output.is_absolute():
        raise ValueError("Output folder must be an absolute path")
    targets = validate_targets(targets)
    output.mkdir(parents=True, exist_ok=True)

    client = GraphClient(tenant_id, client_id, client_secret, opener=opener)
    client.authenticate()
    results = []
    for target in targets:
        mailbox, message_id = target["MailboxOwnerUPN"], target["InternetMessageId"]
        report = {field: "" for field in REPORT_FIELDS}
        report.update(target)
        try:
            user = quote(mailbox, safe="")
            escaped = message_id.replace("'", "''")
            params = urlencode({
                "$filter": f"internetMessageId eq '{escaped}'",
                "$select": "id,subject,internetMessageId,hasAttachments",
                "$top": "25",
            })
            messages = list(client.pages(f"{GRAPH_ROOT}/users/{user}/messages?{params}"))
            if not messages:
                report["Status"] = "Not found"
                results.append(report)
                continue
            mailbox_dir = output / f"{_safe_name(mailbox, 'mailbox')}_emails"
            for index, message in enumerate(messages, 1):
                graph_id = quote(str(message.get("id", "")), safe="")
                message_dir = mailbox_dir / _safe_name(message_id.strip("<>"), f"message-{index}")
                if len(messages) > 1:
                    message_dir = message_dir / str(index)
                message_dir.mkdir(parents=True, exist_ok=True)
                eml_path = message_dir / f"{_safe_name(message.get('subject'), 'message')}.eml"
                eml_path.write_bytes(client.get(f"{GRAPH_ROOT}/users/{user}/messages/{graph_id}/$value", binary=True))
                attachment_count = 0
                if message.get("hasAttachments"):
                    attachment_url = f"{GRAPH_ROOT}/users/{user}/messages/{graph_id}/attachments?$top=100"
                    for attachment in client.pages(attachment_url):
                        if attachment.get("@odata.type") != "#microsoft.graph.fileAttachment":
                            continue
                        content = attachment.get("contentBytes")
                        if not content and attachment.get("id"):
                            attachment_id = quote(str(attachment["id"]), safe="")
                            detail = client.get(f"{GRAPH_ROOT}/users/{user}/messages/{graph_id}/attachments/{attachment_id}")
                            content = detail.get("contentBytes")
                        if not content:
                            continue
                        filename = _safe_name(attachment.get("name"), f"attachment-{attachment_count + 1}")
                        candidate = message_dir / filename
                        if candidate.exists():
                            candidate = message_dir / f"{candidate.stem}-{attachment_count + 1}{candidate.suffix}"
                        candidate.write_bytes(base64.b64decode(content))
                        attachment_count += 1
                item = dict(report)
                item.update({
                    "Subject": message.get("subject", ""), "Status": "Collected",
                    "EmlPath": str(eml_path), "AttachmentCount": attachment_count,
                })
                results.append(item)
        except Exception as exc:  # Continue collecting the remaining requested messages.
            report.update({"Status": "Error", "Error": str(exc)})
            results.append(report)

    report_path = output / "Email_Report.csv"
    with report_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    return {
        "requested": len(targets),
        "collected": sum(1 for row in results if row["Status"] == "Collected"),
        "notFound": sum(1 for row in results if row["Status"] == "Not found"),
        "errors": sum(1 for row in results if row["Status"] == "Error"),
        "outputFolder": str(output),
        "reportPath": str(report_path),
    }
