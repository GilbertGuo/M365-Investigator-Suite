import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict


APP_ID_RE = re.compile(r"(?:app|application)id$", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
REFERENCE_PATH = Path(__file__).with_name("app_id_names.json")
UNKNOWN_APP = "Not listed in Microsoft first-party reference"


@lru_cache(maxsize=1)
def app_reference() -> Dict[str, Any]:
    return json.loads(REFERENCE_PATH.read_text(encoding="utf-8"))


def is_app_id_field(name: str) -> bool:
    return not str(name).startswith("AppMapping.") and bool(APP_ID_RE.search(str(name)))


def add_app_name_mapping(row: Dict[str, Any]) -> Dict[str, Any]:
    apps = app_reference()["apps"]
    for field, value in list(row.items()):
        app_id = str(value or "").strip().lower()
        if is_app_id_field(field) and UUID_RE.fullmatch(app_id):
            row[f"AppMapping.{field}"] = apps.get(app_id, UNKNOWN_APP)
    return row
