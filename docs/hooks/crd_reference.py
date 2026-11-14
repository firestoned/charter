"""MkDocs hook: render IAMClient field tables from deploy/crd.yaml.

A page includes a table by writing one of these markers on its own line:

    <!-- crd-fields: spec -->
    <!-- crd-fields: status -->

The tables are generated from the CRD's OpenAPI schema at build time, so the
reference always matches the CRD, which CI keeps in sync with the Rust types
(`cargo run -- crd | diff - deploy/crd.yaml`).
"""

from __future__ import annotations

import json
import pathlib
import re

import yaml

CRD = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "crd.yaml"
MARKER = re.compile(r"^<!-- crd-fields: (spec|status) -->$", re.MULTILINE)

_schema: dict | None = None


def _load() -> dict:
    global _schema
    if _schema is None:
        crd = yaml.safe_load(CRD.read_text())
        versions = crd["spec"]["versions"]
        served = [v for v in versions if v.get("storage")] or versions
        _schema = served[0]["schema"]["openAPIV3Schema"]["properties"]
    return _schema


def _type(node: dict) -> str:
    t = node.get("type")
    if t == "array":
        return f"[]{_type(node.get('items', {}))}"
    if node.get("enum"):
        return " \\| ".join(f"`{e}`" for e in node["enum"])
    if t is None and node.get("anyOf"):
        return " or ".join(_type(a) for a in node["anyOf"])
    if t == "object" and "properties" not in node:
        return "object"
    return t or "any"


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _rows(node: dict, prefix: str, required: set[str]) -> list[str]:
    rows = []
    for name, child in node.get("properties", {}).items():
        path = f"{prefix}.{name}" if prefix else name
        item = child.get("items", {}) if child.get("type") == "array" else child
        default = child.get("default")
        default = f"`{json.dumps(default)}`" if default is not None else ""
        nullable = " (optional)" if child.get("nullable") else ""
        rows.append(
            f"| `{path}` | {_type(child)}{nullable} | {'yes' if name in required else ''} "
            f"| {default} | {_cell(child.get('description', ''))} |"
        )
        if item.get("properties"):
            sub = f"{path}[]" if child.get("type") == "array" else path
            rows.extend(_rows(item, sub, set(item.get("required", []))))
    return rows


def _table(section: str) -> str:
    node = _load()[section]
    head = [
        "| Field | Type | Required | Default | Description |",
        "|---|---|---|---|---|",
    ]
    return "\n".join(head + _rows(node, "", set(node.get("required", []))))


def on_page_markdown(markdown: str, **_kwargs) -> str:
    return MARKER.sub(lambda m: _table(m.group(1)), markdown)
