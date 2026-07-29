import csv
import hashlib
import json
import re
import secrets
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional

from .app_mapping import add_app_name_mapping
from .core import IP_API_OUTPUT_FIELDS, RDAP_OUTPUT_FIELDS, add_inbox_rule_review, add_login_review, analyze_impossible_travel, analyze_suspicious_logins, build_event_summary, build_message_trace_event_summary, email_domains, extract_message_subject_pairs, format_message_id, hunt_suspicious_message_trace, message_trace_ip_columns, normalize_ip, normalize_message_id_display, parse_message_trace_rows, parse_rows, read_upload, row_columns, summarize, utc_now

SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


class CaseStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = RLock()
        self._rows_cache = OrderedDict()
        self._overview_cache: Dict[str, Dict[str, Any]] = {}
        self._message_trace_rows_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._message_trace_overview_cache: Dict[str, Dict[str, Any]] = {}

    def invalidate(self, case_id: str) -> None:
        with self.lock:
            self._rows_cache.pop(case_id, None)
            self._overview_cache.pop(case_id, None)

    def invalidate_message_trace(self, case_id: str, trace_id: str = "") -> None:
        with self.lock:
            if trace_id:
                key = f"{case_id}:{trace_id}"
                self._message_trace_rows_cache.pop(key, None)
                self._message_trace_overview_cache.pop(key, None)
            else:
                prefix = f"{case_id}:"
                for cache in (self._message_trace_rows_cache, self._message_trace_overview_cache):
                    for key in [key for key in cache if key.startswith(prefix)]:
                        cache.pop(key, None)

    def _dir(self, case_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{12}", case_id):
            raise KeyError("Case not found")
        path = self.root / case_id
        if path.is_dir(): return path
        for case_dir in self.root.iterdir():
            candidate = case_dir / "ual" / "datasets" / case_id
            if candidate.is_dir(): return candidate
        raise KeyError("Case or UAL dataset not found")

    def list(self) -> List[Dict[str, Any]]:
        cases = []
        for path in self.root.iterdir():
            try:
                cases.append(json.loads((path / "meta.json").read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
        return sorted(cases, key=lambda x: x.get("createdAt", ""), reverse=True)

    def delete(self, case_id: str) -> Dict[str, Any]:
        case_dir = self._dir(case_id)
        meta = self.meta(case_id)
        trash = self.root / ".trash"
        trash.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = trash / f"{case_id}-{stamp}"
        counter = 2
        while destination.exists():
            destination = trash / f"{case_id}-{stamp}-{counter}"
            counter += 1
        case_dir.rename(destination)
        self.invalidate(case_id)
        return {**meta, "deletedAt": utc_now(), "trashPath": str(destination)}

    def create(self, name: str, filename: str, raw: bytes) -> Dict[str, Any]:
        if len(raw) > 250 * 1024 * 1024:
            raise ValueError("File exceeds the 250 MB upload limit")
        source = read_upload(filename, raw)
        if not source:
            raise ValueError("The uploaded file contains no records")
        rows, errors = parse_rows(source)
        case_id = secrets.token_hex(6)
        case_dir = self.root / case_id
        case_dir.mkdir()
        safe_filename = SAFE_NAME.sub("_", Path(filename).name)[:180]
        source_dir = case_dir / "source"
        source_dir.mkdir()
        (source_dir / safe_filename).write_bytes(raw)
        meta = {"id": case_id, "name": (name or Path(filename).stem).strip()[:120], "sourceFile": safe_filename,
                "sourceSha256": hashlib.sha256(raw).hexdigest(), "createdAt": utc_now(), "rowCount": len(rows),
                "columnCount": len(row_columns(rows)), "parseErrors": errors}
        (case_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        with (case_dir / "rows.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return meta

    def create_case(self, name: str) -> Dict[str, Any]:
        clean_name = str(name or "").strip()[:120]
        if not clean_name:
            raise ValueError("Enter a case name")
        case_id = secrets.token_hex(6)
        case_dir = self.root / case_id
        case_dir.mkdir()
        meta = {"id": case_id, "name": clean_name, "createdAt": utc_now(), "rowCount": 0,
                "columnCount": 0, "ualDatasetCount": 0, "sourceFile": "No UAL datasets"}
        (case_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return meta

    def ual_datasets(self, case_id: str) -> List[Dict[str, Any]]:
        if not re.fullmatch(r"[a-f0-9]{12}", str(case_id or "")):
            raise KeyError("Case not found")
        case_dir = self.root / case_id
        if not case_dir.is_dir() or not (case_dir / "meta.json").is_file():
            raise KeyError("Case not found")
        datasets = []
        if (case_dir / "rows.jsonl").is_file():
            meta = self.meta(case_id)
            try:
                with (case_dir / "rows.jsonl").open(encoding="utf-8") as handle:
                    legacy_row_count = sum(1 for line in handle if line.strip())
            except OSError:
                legacy_row_count = int(meta.get("rowCount", 0))
            datasets.append({**meta, "id": case_id, "name": meta.get("ualName") or Path(meta.get("sourceFile", "UAL export")).stem,
                             "uploadedAt": meta.get("createdAt", ""), "rowCount": legacy_row_count, "legacy": True})
        datasets_root = case_dir / "ual" / "datasets"
        if datasets_root.is_dir():
            for path in datasets_root.iterdir():
                try: datasets.append(json.loads((path / "meta.json").read_text(encoding="utf-8")))
                except (OSError, ValueError): pass
        return sorted(datasets, key=lambda item: item.get("uploadedAt", item.get("createdAt", "")), reverse=True)

    def _refresh_case_ual_summary(self, case_id: str) -> None:
        case_dir = self.root / case_id
        meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))
        datasets = self.ual_datasets(case_id)
        meta.update({"rowCount": sum(int(item.get("rowCount", 0)) for item in datasets),
                     "ualDatasetCount": len(datasets)})
        if not (case_dir / "rows.jsonl").is_file():
            meta["sourceFile"] = f"{len(datasets)} UAL dataset{'s' if len(datasets) != 1 else ''}"
        (case_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def create_ual_dataset(self, case_id: str, filename: str, raw: bytes, name: str = "") -> Dict[str, Any]:
        if not re.fullmatch(r"[a-f0-9]{12}", str(case_id or "")):
            raise KeyError("Case not found")
        if len(raw) > 250 * 1024 * 1024:
            raise ValueError("File exceeds the 250 MB upload limit")
        source = read_upload(filename, raw)
        if not source:
            raise ValueError("The uploaded UAL file contains no records")
        rows, errors = parse_rows(source)
        dataset_id = secrets.token_hex(6)
        dataset_dir = self.root / case_id / "ual" / "datasets" / dataset_id
        if not (self.root / case_id / "meta.json").is_file():
            raise KeyError("Case not found")
        source_dir = dataset_dir / "source"
        source_dir.mkdir(parents=True)
        safe_filename = SAFE_NAME.sub("_", Path(filename).name)[:180]
        (source_dir / safe_filename).write_bytes(raw)
        meta = {"id": dataset_id, "name": (name or Path(filename).stem).strip()[:120],
                "sourceFile": safe_filename, "sourceSha256": hashlib.sha256(raw).hexdigest(),
                "uploadedAt": utc_now(), "rowCount": len(rows), "columnCount": len(row_columns(rows)),
                "parseErrors": errors, "caseId": case_id}
        (dataset_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        with (dataset_dir / "rows.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows: handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._refresh_case_ual_summary(case_id)
        return meta

    def delete_ual_dataset(self, case_id: str, dataset_id: str) -> Dict[str, Any]:
        if not re.fullmatch(r"[a-f0-9]{12}", str(case_id or "")) or not re.fullmatch(r"[a-f0-9]{12}", str(dataset_id or "")):
            raise KeyError("UAL dataset not found")
        case_dir = self.root / case_id
        datasets = {item["id"]: item for item in self.ual_datasets(case_id)}
        if dataset_id not in datasets: raise KeyError("UAL dataset not found")
        meta = datasets[dataset_id]
        trash = case_dir / ".trash-ual-datasets"
        trash.mkdir(exist_ok=True)
        destination = trash / f"{dataset_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        if dataset_id == case_id:
            destination.mkdir()
            names = ("rows.jsonl", "source", "enrichment.json", "enrichment-columns.json", "travel-analysis.json",
                     "suspicious-login-analysis.json", "message-subject-analysis.json", "row-tags.json", "event-summary.json")
            for name in names:
                source = case_dir / name
                if source.exists(): source.rename(destination / name)
        else:
            (case_dir / "ual" / "datasets" / dataset_id).rename(destination)
        self.invalidate(dataset_id)
        self._refresh_case_ual_summary(case_id)
        return meta

    def meta(self, case_id: str) -> Dict[str, Any]:
        return json.loads((self._dir(case_id) / "meta.json").read_text(encoding="utf-8"))

    def base_rows(self, case_id: str) -> List[Dict[str, Any]]:
        with (self._dir(case_id) / "rows.jsonl").open(encoding="utf-8") as handle:
            return [add_app_name_mapping(normalize_message_id_display(add_login_review(add_inbox_rule_review(json.loads(line))))) for line in handle if line.strip()]

    def enrichment_columns(self, case_id: str) -> List[str]:
        path = self._dir(case_id) / "enrichment-columns.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return []

    def save_enrichment_column(self, case_id: str, column: str) -> None:
        columns = self.enrichment_columns(case_id)
        if column not in columns: columns.append(column)
        (self._dir(case_id) / "enrichment-columns.json").write_text(json.dumps(columns, indent=2), encoding="utf-8")
        self.invalidate(case_id)

    def rows(self, case_id: str) -> List[Dict[str, Any]]:
        with self.lock:
            cached = self._rows_cache.get(case_id)
            if cached is not None:
                self._rows_cache.move_to_end(case_id)
                return cached
        rows, results = self.base_rows(case_id), self.enrichment(case_id)
        for column in self.enrichment_columns(case_id):
            for row in rows:
                ip = normalize_ip(row.get(column))
                if not ip:
                    continue
                result = results.get(ip, {})
                for suffix in list(IP_API_OUTPUT_FIELDS) + ["IP_Class", "Lookup_Status", "Error"]:
                    row[f"{column}_IPAPI_{suffix}"] = result.get(suffix, "")
        travel = self.travel_analysis(case_id)
        for row in rows:
            finding = travel.get(str(row.get("_Row", "")), {})
            row.update({f"Travel.{key}": value for key, value in finding.items()})
        suspicious = self.suspicious_login_analysis(case_id)
        for row in rows:
            finding = suspicious.get(str(row.get("_Row", "")), {})
            row.update({f"SuspiciousLogin.{key}": value for key, value in finding.items()})
        message_subjects = self.message_subject_analysis(case_id)
        for row in rows:
            finding = message_subjects.get(str(row.get("_Row", "")), {})
            row.update({f"MessageSubject.{key}": value for key, value in finding.items()})
        tagged_rows = self.row_tags(case_id)
        for row in rows:
            if str(row.get("_Row", "")) in tagged_rows:
                row["Review.Tag"] = "Of interest"
        event_rows = self.event_rows(case_id)
        if event_rows is not False:
            for row in rows:
                if event_rows is None or str(row.get("_Row", "")) in event_rows:
                    row["Event"] = build_event_summary(row)
        with self.lock:
            existing = self._rows_cache.get(case_id)
            if existing is not None:
                return existing
            self._rows_cache[case_id] = rows
            while len(self._rows_cache) > 1:
                evicted_case, _ = self._rows_cache.popitem(last=False)
                self._overview_cache.pop(evicted_case, None)
        return rows

    def message_subject_analysis(self, case_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._dir(case_id) / "message-subject-analysis.json"
        try:
            findings = json.loads(path.read_text(encoding="utf-8")).get("findings", {})
            for finding in findings.values():
                finding["InternetMessageIDs"] = "; ".join(format_message_id(item) for item in str(finding.get("InternetMessageIDs", "")).split(";") if item.strip())
                lines = []
                for line in str(finding.get("Pairs", "")).splitlines():
                    message_id, separator, subject = line.partition(" → ")
                    lines.append(f"{format_message_id(message_id)}{separator}{subject}" if separator else line)
                finding["Pairs"] = "\n".join(lines)
            return findings
        except (OSError, ValueError, AttributeError): return {}

    def event_rows(self, case_id: str):
        path = self._dir(case_id) / "event-summary.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, AttributeError):
            return False
        if "rows" not in payload:
            return None  # Preserve event columns created by versions that targeted every row.
        if payload.get("rows") is None:
            return None
        return {str(value) for value in payload.get("rows", [])}

    def enable_events(self, case_id: str, row_numbers: List[Any]) -> Dict[str, Any]:
        requested = {str(value).strip() for value in row_numbers if str(value or "").strip()}
        if any(not re.fullmatch(r"\d+", row_id) for row_id in requested):
            raise ValueError("Filtered results contain an invalid source row")
        existing = self.event_rows(case_id)
        selected = requested if existing is False else None if existing is None else existing | requested
        payload = {"generatedAt": utc_now(), "column": "Event", "rows": sorted(selected, key=int) if selected is not None else None}
        path = self._dir(case_id) / "event-summary.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
        self.invalidate(case_id)
        return {**payload, "matched": len(requested), "enabled": None if selected is None else len(selected)}

    def _message_trace_dir(self, case_id: str, trace_id: str) -> Path:
        if trace_id == "legacy":
            path = self._dir(case_id) / "message-trace"
        elif re.fullmatch(r"[a-f0-9]{12}", str(trace_id or "")):
            path = self._dir(case_id) / "message-trace" / "traces" / trace_id
        else:
            raise KeyError("Message Trace not found")
        if not (path / "meta.json").is_file():
            raise KeyError("Message Trace not found")
        return path

    def message_traces(self, case_id: str) -> List[Dict[str, Any]]:
        root = self._dir(case_id) / "message-trace"
        traces = []
        if (root / "meta.json").is_file():
            try:
                traces.append({"id": "legacy", **json.loads((root / "meta.json").read_text(encoding="utf-8"))})
            except (OSError, ValueError):
                pass
        traces_root = root / "traces"
        if traces_root.is_dir():
            for path in traces_root.iterdir():
                try:
                    traces.append({"id": path.name, **json.loads((path / "meta.json").read_text(encoding="utf-8"))})
                except (OSError, ValueError):
                    pass
        return sorted(traces, key=lambda item: item.get("uploadedAt", ""), reverse=True)

    def create_message_trace(self, case_id: str, filename: str, raw: bytes, name: str = "") -> Dict[str, Any]:
        if len(raw) > 250 * 1024 * 1024:
            raise ValueError("File exceeds the 250 MB upload limit")
        source = read_upload(filename, raw)
        rows = parse_message_trace_rows(source)
        if not rows:
            raise ValueError("The Message Trace CSV contains no records")
        trace_id = secrets.token_hex(6)
        trace_dir = self._dir(case_id) / "message-trace" / "traces" / trace_id
        source_dir = trace_dir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = SAFE_NAME.sub("_", Path(filename).name)[:180]
        (source_dir / safe_filename).write_bytes(raw)
        with (trace_dir / "rows.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        meta = {"id": trace_id, "name": (name or Path(filename).stem).strip()[:120],
                "sourceFile": safe_filename, "sourceSha256": hashlib.sha256(raw).hexdigest(),
                "uploadedAt": utc_now(), "rowCount": len(rows), "columnCount": len(row_columns(rows))}
        (trace_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.invalidate_message_trace(case_id, trace_id)
        return meta

    def delete_message_trace(self, case_id: str, trace_id: str) -> Dict[str, Any]:
        trace_dir = self._message_trace_dir(case_id, trace_id)
        meta = self.message_trace_meta(case_id, trace_id)
        trash = self._dir(case_id) / ".trash-message-traces"
        trash.mkdir(exist_ok=True)
        destination = trash / f"{trace_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        counter = 2
        while destination.exists():
            destination = trash / f"{trace_id}-{counter}"
            counter += 1
        if trace_id == "legacy":
            destination.mkdir()
            for name in ("meta.json", "rows.jsonl", "enrichment.json", "enrichment-columns.json",
                         "domain-enrichment.json", "domain-enrichment-columns.json",
                         "suspicious-mail-hunt.json", "row-tags.json", "event-summary.json", "source"):
                source = trace_dir / name
                if source.exists():
                    source.rename(destination / name)
        else:
            trace_dir.rename(destination)
        self.invalidate_message_trace(case_id, trace_id)
        return meta

    def message_trace_meta(self, case_id: str, trace_id: str) -> Dict[str, Any]:
        path = self._message_trace_dir(case_id, trace_id) / "meta.json"
        try:
            return {"id": trace_id, **json.loads(path.read_text(encoding="utf-8"))}
        except (OSError, ValueError):
            return {}

    def message_trace_enrichment(self, case_id: str, trace_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._message_trace_dir(case_id, trace_id) / "enrichment.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {}

    def message_trace_enrichment_columns(self, case_id: str, trace_id: str) -> List[str]:
        path = self._message_trace_dir(case_id, trace_id) / "enrichment-columns.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return []

    def save_message_trace_enrichment(self, case_id: str, trace_id: str, data: Dict[str, Dict[str, Any]], columns: List[str]) -> None:
        trace_dir = self._message_trace_dir(case_id, trace_id)
        (trace_dir / "enrichment.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        existing = self.message_trace_enrichment_columns(case_id, trace_id)
        combined = existing + [column for column in columns if column not in existing]
        (trace_dir / "enrichment-columns.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
        self.invalidate_message_trace(case_id, trace_id)

    def message_trace_domain_enrichment(self, case_id: str, trace_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._message_trace_dir(case_id, trace_id) / "domain-enrichment.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {}

    def message_trace_domain_columns(self, case_id: str, trace_id: str) -> List[str]:
        path = self._message_trace_dir(case_id, trace_id) / "domain-enrichment-columns.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return []

    def save_message_trace_domain_enrichment(self, case_id: str, trace_id: str, data: Dict[str, Dict[str, Any]], columns: List[str]) -> None:
        trace_dir = self._message_trace_dir(case_id, trace_id)
        (trace_dir / "domain-enrichment.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        existing = self.message_trace_domain_columns(case_id, trace_id)
        combined = existing + [column for column in columns if column not in existing]
        (trace_dir / "domain-enrichment-columns.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
        self.invalidate_message_trace(case_id, trace_id)

    def message_trace_hunt_analysis(self, case_id: str, trace_id: str) -> Dict[str, Any]:
        path = self._message_trace_dir(case_id, trace_id) / "suspicious-mail-hunt.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {}

    def hunt_message_trace(self, case_id: str, trace_id: str, rows: List[Dict[str, Any]], **criteria) -> Dict[str, Any]:
        analysis = hunt_suspicious_message_trace(
            rows, self.message_trace_domain_enrichment(case_id, trace_id),
            self.message_trace_domain_columns(case_id, trace_id), **criteria,
        )
        payload = {**analysis, "criteria": criteria, "analyzedAt": utc_now()}
        path = self._message_trace_dir(case_id, trace_id) / "suspicious-mail-hunt.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
        self.invalidate_message_trace(case_id, trace_id)
        return payload

    def message_trace_row_tags(self, case_id: str, trace_id: str) -> set:
        path = self._message_trace_dir(case_id, trace_id) / "row-tags.json"
        try: return {str(value) for value in json.loads(path.read_text(encoding="utf-8")).get("rows", [])}
        except (OSError, ValueError, AttributeError): return set()

    def message_trace_event_rows(self, case_id: str, trace_id: str):
        path = self._message_trace_dir(case_id, trace_id) / "event-summary.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, AttributeError):
            return False
        if payload.get("rows") is None:
            return None
        return {str(value) for value in payload.get("rows", [])}

    def enable_message_trace_events(self, case_id: str, trace_id: str, row_numbers: List[Any]) -> Dict[str, Any]:
        requested = {str(value).strip() for value in row_numbers if str(value or "").strip()}
        if any(not re.fullmatch(r"\d+", row_id) for row_id in requested):
            raise ValueError("Filtered Message Trace results contain an invalid source row")
        available = {str(row.get("_Row", "")) for row in self.message_trace_rows(case_id, trace_id)}
        requested &= available
        if not requested:
            raise ValueError("The current Message Trace filters contain no rows for Event generation")
        existing = self.message_trace_event_rows(case_id, trace_id)
        selected = requested if existing is False else None if existing is None else existing | requested
        payload = {"generatedAt": utc_now(), "column": "Event",
                   "rows": sorted(selected, key=int) if selected is not None else None}
        path = self._message_trace_dir(case_id, trace_id) / "event-summary.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
        self.invalidate_message_trace(case_id, trace_id)
        return {**payload, "matched": len(requested), "enabled": None if selected is None else len(selected)}

    def set_message_trace_row_tags(self, case_id: str, trace_id: str, row_numbers: List[Any], tagged: bool) -> Dict[str, Any]:
        requested = {str(value).strip() for value in row_numbers if str(value or "").strip()}
        if any(not re.fullmatch(r"\d+", row_id) for row_id in requested):
            raise ValueError("Message Trace results contain an invalid source row")
        available = {str(row.get("_Row", "")) for row in self.message_trace_rows(case_id, trace_id)}
        row_ids = requested & available
        if not row_ids:
            raise ValueError("Choose a valid Message Trace row")
        tags = self.message_trace_row_tags(case_id, trace_id)
        before = set(tags)
        if tagged: tags.update(row_ids)
        else: tags.difference_update(row_ids)
        payload = {"updatedAt": utc_now(), "rows": sorted(tags, key=int)}
        path = self._message_trace_dir(case_id, trace_id) / "row-tags.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
        self.invalidate_message_trace(case_id, trace_id)
        changed = len(tags - before) if tagged else len(before - tags)
        return {"matched": len(row_ids), "changed": changed, "tagged": tagged, "taggedCount": len(tags)}

    def message_trace_rows(self, case_id: str, trace_id: str) -> List[Dict[str, Any]]:
        key = f"{case_id}:{trace_id}"
        with self.lock:
            cached = self._message_trace_rows_cache.get(key)
            if cached is not None:
                return cached
        path = self._message_trace_dir(case_id, trace_id) / "rows.jsonl"
        with path.open(encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        enrichment = self.message_trace_enrichment(case_id, trace_id)
        for column in self.message_trace_enrichment_columns(case_id, trace_id):
            for row in rows:
                ip = normalize_ip(row.get(column))
                if not ip:
                    continue
                result = enrichment.get(ip, {})
                for suffix in list(IP_API_OUTPUT_FIELDS) + ["IP_Class", "Lookup_Status", "Error"]:
                    row[f"{column}_IPAPI_{suffix}"] = result.get(suffix, "")
        domain_enrichment = self.message_trace_domain_enrichment(case_id, trace_id)
        for column in self.message_trace_domain_columns(case_id, trace_id):
            for row in rows:
                domains = email_domains(row.get(column))
                for suffix in RDAP_OUTPUT_FIELDS:
                    values = []
                    for domain in domains:
                        value = domain_enrichment.get(domain, {}).get(suffix, "")
                        if str(value).strip() and str(value) not in values:
                            values.append(str(value))
                    row[f"{column}_WHOIS_{suffix}"] = "; ".join(values)
        hunt = self.message_trace_hunt_analysis(case_id, trace_id).get("findings", {})
        for row in rows:
            finding = hunt.get(str(row.get("_Row", "")), {})
            row.update({f"MessageTraceHunt.{key}": value for key, value in finding.items()})
        tagged_rows = self.message_trace_row_tags(case_id, trace_id)
        for row in rows:
            if str(row.get("_Row", "")) in tagged_rows:
                row["Review.Tag"] = "Of interest"
        event_rows = self.message_trace_event_rows(case_id, trace_id)
        if event_rows is not False:
            for row in rows:
                if event_rows is None or str(row.get("_Row", "")) in event_rows:
                    row["Event"] = build_message_trace_event_summary(row)
        with self.lock:
            self._message_trace_rows_cache[key] = rows
        return rows

    def message_trace_overview(self, case_id: str, trace_id: str) -> Dict[str, Any]:
        key = f"{case_id}:{trace_id}"
        with self.lock:
            cached = self._message_trace_overview_cache.get(key)
            if cached is not None:
                return cached
        meta = self.message_trace_meta(case_id, trace_id)
        if not meta:
            return {"exists": False}
        rows = self.message_trace_rows(case_id, trace_id)
        columns = row_columns(rows)
        senders = {str(row.get("SenderAddress", "")).casefold() for row in rows if row.get("SenderAddress")}
        recipients = {str(row.get("RecipientAddress", "")).casefold() for row in rows if row.get("RecipientAddress")}
        ips = {ip for row in rows for column in message_trace_ip_columns(columns) if (ip := normalize_ip(row.get(column)))}
        overview = {"exists": True, "meta": meta, "columns": columns,
                    "enrichmentColumns": self.message_trace_enrichment_columns(case_id, trace_id),
                    "domainEnrichmentColumns": self.message_trace_domain_columns(case_id, trace_id),
                    "summary": {"rows": len(rows), "columns": len(columns), "senders": len(senders),
                                "recipients": len(recipients), "ips": len(ips),
                                "tagged": len(self.message_trace_row_tags(case_id, trace_id))}}
        with self.lock:
            self._message_trace_overview_cache[key] = overview
        return overview

    def row_tags(self, case_id: str) -> set:
        path = self._dir(case_id) / "row-tags.json"
        try:
            return {str(value) for value in json.loads(path.read_text(encoding="utf-8")).get("rows", [])}
        except (OSError, ValueError, AttributeError):
            return set()

    def set_row_tag(self, case_id: str, row_number: Any, tagged: bool) -> Dict[str, Any]:
        row_id = str(row_number or "").strip()
        if not row_id or not re.fullmatch(r"\d+", row_id):
            raise ValueError("Choose a valid source row")
        with self.lock:
            cached_rows = self._rows_cache.get(case_id)
            if cached_rows is None:
                cached_rows = self.rows(case_id)
            tagged_row = next((row for row in cached_rows if str(row.get("_Row", "")) == row_id), None)
            if tagged_row is None:
                raise ValueError("Source row does not exist in this case")
            tags = self.row_tags(case_id)
            if tagged: tags.add(row_id)
            else: tags.discard(row_id)
            payload = {"updatedAt": utc_now(), "rows": sorted(tags, key=int)}
            path = self._dir(case_id) / "row-tags.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(path)

            if tagged: tagged_row["Review.Tag"] = "Of interest"
            else: tagged_row.pop("Review.Tag", None)
            cached_overview = self._overview_cache.get(case_id)
            if cached_overview is not None:
                columns = cached_overview["columns"]
                has_column = "Review.Tag" in columns
                if tags and not has_column: columns.append("Review.Tag")
                elif not tags and has_column: columns.remove("Review.Tag")
                cached_overview["summary"]["columns"] = len(columns)
                cached_overview["summary"]["tagged"] = len(tags)
        return {"row": row_id, "tagged": tagged, "taggedCount": len(tags)}

    def set_row_tags(self, case_id: str, row_numbers: List[Any], tagged: bool) -> Dict[str, Any]:
        requested = {str(value).strip() for value in row_numbers if str(value or "").strip()}
        if any(not re.fullmatch(r"\d+", row_id) for row_id in requested):
            raise ValueError("Filtered results contain an invalid source row")
        with self.lock:
            cached_rows = self._rows_cache.get(case_id)
            if cached_rows is None:
                cached_rows = self.rows(case_id)
            available = {str(row.get("_Row", "")) for row in cached_rows}
            row_ids = requested & available
            tags = self.row_tags(case_id)
            before = set(tags)
            if tagged: tags.update(row_ids)
            else: tags.difference_update(row_ids)
            payload = {"updatedAt": utc_now(), "rows": sorted(tags, key=int)}
            path = self._dir(case_id) / "row-tags.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(path)

            for row in cached_rows:
                if str(row.get("_Row", "")) not in row_ids: continue
                if tagged: row["Review.Tag"] = "Of interest"
                else: row.pop("Review.Tag", None)
            cached_overview = self._overview_cache.get(case_id)
            if cached_overview is not None:
                columns = cached_overview["columns"]
                if tags and "Review.Tag" not in columns: columns.append("Review.Tag")
                elif not tags and "Review.Tag" in columns: columns.remove("Review.Tag")
                cached_overview["summary"]["columns"] = len(columns)
                cached_overview["summary"]["tagged"] = len(tags)
        changed = len(tags - before) if tagged else len(before - tags)
        return {"matched": len(row_ids), "changed": changed, "tagged": tagged, "taggedCount": len(tags)}

    def extract_message_subjects(self, case_id: str) -> Dict[str, Any]:
        findings, unique_pairs = {}, set()
        for row in self.base_rows(case_id):
            pairs = extract_message_subject_pairs(row)
            if not pairs:
                continue
            unique_pairs.update(pairs)
            findings[str(row.get("_Row", ""))] = {
                "InternetMessageIDs": "; ".join(message_id for message_id, _ in pairs),
                "Subjects": "; ".join(subject or "(no subject)" for _, subject in pairs),
                "Pairs": "\n".join(f"{message_id} → {subject or '(no subject)'}" for message_id, subject in pairs),
            }
        payload = {"analyzedAt": utc_now(), "pairCount": len(unique_pairs), "rowCount": len(findings), "findings": findings}
        with self.lock:
            (self._dir(case_id) / "message-subject-analysis.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        self.invalidate(case_id)
        return payload

    def travel_analysis(self, case_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._dir(case_id) / "travel-analysis.json"
        try: return json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        except (OSError, ValueError, AttributeError): return {}

    def hunt_impossible_travel(self, case_id: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        findings = analyze_impossible_travel(self.base_rows(case_id), self.enrichment(case_id),
                                             self.enrichment_columns(case_id), options)
        payload = {"analyzedAt": utc_now(), "method": "Country/region temporal heuristic",
                   "findingCount": len(findings), "options": options or {}, "findings": findings}
        (self._dir(case_id) / "travel-analysis.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.invalidate(case_id)
        return payload

    def suspicious_login_analysis(self, case_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._dir(case_id) / "suspicious-login-analysis.json"
        try: return json.loads(path.read_text(encoding="utf-8")).get("findings", {})
        except (OSError, ValueError, AttributeError): return {}

    def hunt_suspicious_logins(self, case_id: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        findings = analyze_suspicious_logins(self.base_rows(case_id), self.enrichment(case_id),
                                             self.enrichment_columns(case_id), options)
        payload = {"analyzedAt": utc_now(), "method": "Infrastructure and device-posture heuristic",
                   "findingCount": len(findings), "options": options or {}, "findings": findings}
        (self._dir(case_id) / "suspicious-login-analysis.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.invalidate(case_id)
        return payload

    def enrichment(self, case_id: str) -> Dict[str, Dict[str, Any]]:
        path = self._dir(case_id) / "enrichment.json"
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError): return {}

    def save_enrichment(self, case_id: str, data: Dict[str, Dict[str, Any]]) -> None:
        with self.lock:
            (self._dir(case_id) / "enrichment.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            (self._dir(case_id) / "travel-analysis.json").unlink(missing_ok=True)
            (self._dir(case_id) / "suspicious-login-analysis.json").unlink(missing_ok=True)
        self.invalidate(case_id)

    def overview(self, case_id: str) -> Dict[str, Any]:
        with self.lock:
            cached = self._overview_cache.get(case_id)
            if cached is not None:
                return cached
        rows = self.rows(case_id)
        overview = {"meta": self.meta(case_id), "columns": row_columns(rows), "summary": summarize(rows),
                    "enrichment": self.enrichment(case_id), "enrichmentColumns": self.enrichment_columns(case_id)}
        with self.lock:
            self._overview_cache[case_id] = overview
        return overview

    def csv_bytes(self, rows: List[Dict[str, Any]], enrichment: Dict[str, Dict[str, Any]]) -> bytes:
        columns = row_columns(rows)
        output = __import__("io").StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return output.getvalue().encode("utf-8-sig")
