#!/usr/bin/env python3
"""Validate Conduit specification schemas and examples."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "spec" / "schemas"
EXAMPLE_DIR = ROOT / "spec" / "examples"

EXAMPLE_SCHEMAS = {
    "auth": "https://conduit.dev/spec/schemas/auth-v1.schema.json",
    "node-protocol": "https://conduit.dev/spec/schemas/node-protocol-v1.schema.json",
    "trace": "https://conduit.dev/spec/schemas/trace-v1.schema.json",
    "runtime": "https://conduit.dev/spec/schemas/runtime-v1.schema.json",
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path.relative_to(ROOT)}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}"
        ) from exc


def format_error(path: Path, error: Any) -> str:
    location = "$"
    for part in error.absolute_path:
        location += f"[{part}]" if isinstance(part, int) else f".{part}"
    return f"{path.relative_to(ROOT)} {location}: {error.message}"


def main() -> int:
    failures: list[str] = []
    schemas: dict[str, Any] = {}

    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            document = load_json(path)
        except ValueError as exc:
            failures.append(str(exc))
            continue

        if not isinstance(document, dict):
            failures.append(f"{path.relative_to(ROOT)}: schema root must be an object")
            continue

        schema_id = document.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            failures.append(f"{path.relative_to(ROOT)}: schema must have a non-empty $id")
            continue

        if schema_id in schemas:
            failures.append(f"{path.relative_to(ROOT)}: duplicate schema $id {schema_id}")
            continue

        try:
            Draft202012Validator.check_schema(document)
        except Exception as exc:  # jsonschema exposes several schema-error classes
            failures.append(f"{path.relative_to(ROOT)}: invalid JSON Schema: {exc}")
            continue

        schemas[schema_id] = document

    registry = Registry()
    for schema_id, document in schemas.items():
        registry = registry.with_resource(schema_id, Resource.from_contents(document))

    for directory_name, schema_id in EXAMPLE_SCHEMAS.items():
        schema = schemas.get(schema_id)
        if schema is None:
            failures.append(f"missing schema {schema_id} for examples/{directory_name}")
            continue

        directory = EXAMPLE_DIR / directory_name
        if not directory.exists():
            failures.append(f"missing example directory {directory.relative_to(ROOT)}")
            continue

        validator = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )

        examples = sorted(directory.glob("*.json"))
        if not examples:
            failures.append(f"no examples under {directory.relative_to(ROOT)}")
            continue

        for path in examples:
            try:
                instance = load_json(path)
            except ValueError as exc:
                failures.append(str(exc))
                continue

            errors = sorted(
                validator.iter_errors(instance),
                key=lambda error: [str(part) for part in error.absolute_path],
            )
            failures.extend(format_error(path, error) for error in errors)

    if failures:
        print("Specification validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(schemas)} schemas and "
        f"{sum(len(list((EXAMPLE_DIR / name).glob('*.json'))) for name in EXAMPLE_SCHEMAS)} examples."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
