from __future__ import annotations
import html
import json
from pathlib import Path
from typing import Any

def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)

def build_report(rows: list[dict[str, Any]], destination: Path, source_name: str) -> None:
    records = []
    for row in rows:
        records.append({
            "host": str(row.get("Хост", "")),
            "vulnerability": str(row.get("Уязвимость", "")),
            # For network findings the entity is often blank; show endpoint (usually a port) instead.
            "entity": str(row.get("Уязвимая сущность", "")).strip() or str(row.get("endpoint", "")).strip(),
            # Keep endpoint separately so the network widget can identify these rows.
            "endpoint": str(row.get("endpoint", "")).strip(),
            "cvss": row.get("_cvss"),
            "cvss_raw": str(row.get("CVSS", "")),
            "remediation": str(row.get("Как устранить", "")),
            "exploit": row.get("_exploit"),
        })
    payload = json.dumps(records, ensure_ascii=False).replace("</", "<\\/")
    template_dir = Path(__file__).resolve().parent / "templates"
    template = (template_dir / "report.html").read_text(encoding="utf-8")
    css = (template_dir / "style.css").read_text(encoding="utf-8")
    js = (template_dir / "script.js").read_text(encoding="utf-8")
    document = (template.replace("__STYLE__", css)
                      .replace("__SCRIPT__", js)
                      .replace("__SOURCE__", esc(source_name))
                      .replace("__DATA__", payload))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
