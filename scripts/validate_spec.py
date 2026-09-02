#!/usr/bin/env python3
"""Validate Conduit specification schemas and examples."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "spec" / "schemas"
EXAMPLE_DIR = ROOT / "spec" / "examples"
FIXTURE_DIR = ROOT / "spec" / "fixtures"
INVALID_FIXTURE_DIR = FIXTURE_DIR / "invalid"

EXAMPLE_SCHEMAS = {
    "auth": "https://conduit.dev/spec/schemas/auth-v1.schema.json",
    "node-protocol": "https://conduit.dev/spec/schemas/node-protocol-v1.schema.json",
    "trace": "https://conduit.dev/spec/schemas/trace-v1.schema.json",
    "runtime": "https://conduit.dev/spec/schemas/runtime-v1.schema.json",
    "changeset": "https://conduit.dev/spec/schemas/changeset-v1.schema.json",
}

INVALID_FIXTURE_FIELDS = {
    "fixtureVersion",
    "schemaId",
    "validationLayer",
    "validatorKind",
    "instancePath",
    "expectedInvalidReason",
    "instance",
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


def iter_error_tree(error: Any) -> Any:
    yield error
    for child in error.context:
        yield from iter_error_tree(child)


def parse_json_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError("instancePath must be an RFC 6901 JSON Pointer")

    parts: list[str] = []
    for raw_part in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw_part):
            raise ValueError("instancePath contains an invalid JSON Pointer escape")
        parts.append(raw_part.replace("~1", "/").replace("~0", "~"))
    return parts


def resolve_json_pointer(instance: Any, pointer: str) -> Any:
    value = instance
    for part in parse_json_pointer(pointer):
        if isinstance(value, dict):
            if part not in value:
                raise ValueError(f"instancePath does not exist: {pointer}")
            value = value[part]
        elif isinstance(value, list):
            if not part.isdigit() or int(part) >= len(value):
                raise ValueError(f"instancePath does not exist: {pointer}")
            value = value[int(part)]
        else:
            raise ValueError(f"instancePath does not exist: {pointer}")
    return value


def validate_u64_decimal(value: Any) -> str | None:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) is None:
        return "invalid_u64_decimal"
    if int(value) > 18_446_744_073_709_551_615:
        return "u64_overflow"
    return None


def validate_utc_timestamp(value: Any) -> str | None:
    if not isinstance(value, str):
        return "invalid_utc_timestamp"
    if not value.endswith("Z"):
        return "utc_offset_not_z"
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return "invalid_utc_timestamp"
    return None


DOMAIN_VALIDATORS = {
    "u64_decimal": validate_u64_decimal,
    "utc_timestamp": validate_utc_timestamp,
}

SCHEMA_INVALID_REASONS = {
    "invalid_digest": "pattern",
    "malformed_id": "pattern",
    "unknown_schema_version": "const",
}


def validate_canonical_fixture(failures: list[str]) -> int:
    path = FIXTURE_DIR / "canonical-json-v1.json"
    try:
        fixture = load_json(path)
    except ValueError as exc:
        failures.append(str(exc))
        return 0

    if not isinstance(fixture, dict):
        failures.append(f"{path.relative_to(ROOT)}: fixture root must be an object")
        return 0
    if fixture.get("fixtureVersion") != 1:
        failures.append(f"{path.relative_to(ROOT)}: fixtureVersion must be 1")
    if fixture.get("algorithm") != "RFC 8785":
        failures.append(f"{path.relative_to(ROOT)}: algorithm must be RFC 8785")
    if fixture.get("digestAlgorithm") != "SHA-256":
        failures.append(f"{path.relative_to(ROOT)}: digestAlgorithm must be SHA-256")

    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        failures.append(f"{path.relative_to(ROOT)}: cases must be a non-empty array")
        return 0

    names: set[str] = set()
    for index, case in enumerate(cases):
        label = f"{path.relative_to(ROOT)} $.cases[{index}]"
        if not isinstance(case, dict) or set(case) != {
            "name",
            "value",
            "expectedCanonical",
            "expectedSha256",
        }:
            failures.append(f"{label}: canonical case has unexpected fields")
            continue

        name = case["name"]
        if not isinstance(name, str) or not name:
            failures.append(f"{label}.name: must be a non-empty string")
        elif name in names:
            failures.append(f"{label}.name: duplicate case name {name}")
        else:
            names.add(name)

        canonical = case["expectedCanonical"]
        digest = case["expectedSha256"]
        if not isinstance(canonical, str):
            failures.append(f"{label}.expectedCanonical: must be a string")
            continue
        try:
            canonical_value = json.loads(canonical)
        except json.JSONDecodeError as exc:
            failures.append(f"{label}.expectedCanonical: invalid JSON: {exc.msg}")
            continue
        if canonical_value != case["value"]:
            failures.append(f"{label}.expectedCanonical: does not represent value")

        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            failures.append(f"{label}.expectedSha256: must be lowercase SHA-256 hex")
        else:
            actual_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if actual_digest != digest:
                failures.append(
                    f"{label}.expectedSha256: expected {digest}, calculated {actual_digest}"
                )

    return len(cases)


def validate_timestamp_fixture(failures: list[str]) -> int:
    path = FIXTURE_DIR / "utc-timestamp-v1.json"
    try:
        fixture = load_json(path)
    except ValueError as exc:
        failures.append(str(exc))
        return 0

    if not isinstance(fixture, dict) or set(fixture) != {
        "fixtureVersion",
        "contract",
        "cases",
    }:
        failures.append(f"{path.relative_to(ROOT)}: unexpected fixture fields")
        return 0
    if fixture["fixtureVersion"] != 1:
        failures.append(f"{path.relative_to(ROOT)}: fixtureVersion must be 1")
    if fixture["contract"] != "preserve_valid_utc_rfc3339_wire_text":
        failures.append(f"{path.relative_to(ROOT)}: unexpected timestamp contract")

    cases = fixture["cases"]
    if not isinstance(cases, list) or not cases:
        failures.append(f"{path.relative_to(ROOT)}: cases must be a non-empty array")
        return 0

    required_inputs = {
        "2026-09-01T12:00:00.000Z",
        "2026-09-01T12:00:00.120Z",
        "2026-09-01T12:00:00.123456789Z",
    }
    observed_inputs: set[str] = set()
    names: set[str] = set()
    for index, case in enumerate(cases):
        label = f"{path.relative_to(ROOT)} $.cases[{index}]"
        if not isinstance(case, dict) or set(case) != {
            "name",
            "input",
            "expectedWireText",
        }:
            failures.append(f"{label}: unexpected timestamp case fields")
            continue

        name = case["name"]
        value = case["input"]
        expected = case["expectedWireText"]
        if not isinstance(name, str) or not name or name in names:
            failures.append(f"{label}.name: must be non-empty and unique")
        else:
            names.add(name)
        if not isinstance(value, str) or not isinstance(expected, str):
            failures.append(f"{label}: input and expectedWireText must be strings")
            continue
        observed_inputs.add(value)
        if value != expected:
            failures.append(f"{label}: expectedWireText must preserve input exactly")
        if validate_utc_timestamp(value) is not None:
            failures.append(f"{label}.input: must be valid UTC RFC 3339 text")

    missing = required_inputs - observed_inputs
    if missing:
        failures.append(
            f"{path.relative_to(ROOT)}: missing required timestamp cases: "
            f"{', '.join(sorted(missing))}"
        )
    return len(cases)


def validate_invalid_fixtures(
    schemas: dict[str, Any], registry: Registry, failures: list[str]
) -> int:
    paths = sorted(INVALID_FIXTURE_DIR.glob("*.json"))
    if not paths:
        failures.append(f"no invalid fixtures under {INVALID_FIXTURE_DIR.relative_to(ROOT)}")
        return 0

    for path in paths:
        try:
            fixture = load_json(path)
        except ValueError as exc:
            failures.append(str(exc))
            continue

        label = str(path.relative_to(ROOT))
        if not isinstance(fixture, dict) or set(fixture) != INVALID_FIXTURE_FIELDS:
            failures.append(f"{label}: invalid fixture has unexpected fields")
            continue
        if fixture["fixtureVersion"] != 1:
            failures.append(f"{label}: fixtureVersion must be 1")
            continue

        schema_id = fixture["schemaId"]
        schema = schemas.get(schema_id)
        if schema is None:
            failures.append(f"{label}: unknown schemaId {schema_id}")
            continue
        if not isinstance(fixture["expectedInvalidReason"], str) or not fixture[
            "expectedInvalidReason"
        ]:
            failures.append(f"{label}: expectedInvalidReason must be a non-empty string")
            continue

        pointer = fixture["instancePath"]
        if not isinstance(pointer, str):
            failures.append(f"{label}: instancePath must be a string")
            continue
        try:
            target = resolve_json_pointer(fixture["instance"], pointer)
            target_parts = parse_json_pointer(pointer)
        except ValueError as exc:
            failures.append(f"{label}: {exc}")
            continue

        validator = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        schema_errors = list(validator.iter_errors(fixture["instance"]))
        layer = fixture["validationLayer"]
        validator_kind = fixture["validatorKind"]

        if layer == "schema":
            if validator_kind != "json_schema":
                failures.append(f"{label}: schema fixtures must use json_schema")
                continue
            if not schema_errors:
                failures.append(f"{label}: instance unexpectedly passed schema validation")
                continue
            expected_validator = SCHEMA_INVALID_REASONS.get(
                fixture["expectedInvalidReason"]
            )
            if expected_validator is None:
                failures.append(
                    f"{label}: unknown schema expectedInvalidReason "
                    f"{fixture['expectedInvalidReason']}"
                )
                continue
            error_signatures = {
                (tuple(str(part) for part in error.absolute_path), error.validator)
                for root_error in schema_errors
                for error in iter_error_tree(root_error)
            }
            if (tuple(target_parts), expected_validator) not in error_signatures:
                failures.append(
                    f"{label}: schema rejection did not identify {pointer} "
                    f"with validator {expected_validator}"
                )
        elif layer == "domain":
            if schema_errors:
                failures.append(
                    f"{label}: domain fixture must pass its wire schema; "
                    f"first error: {schema_errors[0].message}"
                )
                continue
            domain_validator = DOMAIN_VALIDATORS.get(validator_kind)
            if domain_validator is None:
                failures.append(f"{label}: unknown domain validatorKind {validator_kind}")
                continue
            actual_reason = domain_validator(target)
            if actual_reason is None:
                failures.append(f"{label}: instance unexpectedly passed domain validation")
            elif actual_reason != fixture["expectedInvalidReason"]:
                failures.append(
                    f"{label}: expected {fixture['expectedInvalidReason']}, got {actual_reason}"
                )
        else:
            failures.append(f"{label}: validationLayer must be schema or domain")

    return len(paths)


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

    canonical_case_count = validate_canonical_fixture(failures)
    timestamp_case_count = validate_timestamp_fixture(failures)
    invalid_fixture_count = validate_invalid_fixtures(schemas, registry, failures)

    if failures:
        print("Specification validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(schemas)} schemas and "
        f"{sum(len(list((EXAMPLE_DIR / name).glob('*.json'))) for name in EXAMPLE_SCHEMAS)} "
        f"examples, {canonical_case_count} canonical JSON cases, "
        f"{timestamp_case_count} timestamp cases, and {invalid_fixture_count} "
        "invalid fixtures."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
