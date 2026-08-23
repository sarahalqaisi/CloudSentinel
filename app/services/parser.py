from __future__ import annotations

import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import settings


@dataclass
class ParsedResource:
    address: str
    resource_type: str
    name: str
    provider: str
    configuration: dict[str, Any]
    file_path: str | None = None
    line_number: int | None = None
    region: str | None = None


class ParseError(ValueError):
    pass


def _provider(resource_type: str) -> str:
    return resource_type.split("_", 1)[0] if "_" in resource_type else "generic"


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        in_quote = False
        cut = len(line)
        i = 0
        while i < len(line):
            if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                in_quote = not in_quote
            if not in_quote and line[i:i + 2] == "//":
                cut = i
                break
            if not in_quote and line[i] == "#":
                cut = i
                break
            i += 1
        lines.append(line[:cut])
    return "\n".join(lines)


def _matching_brace(text: str, start: int) -> int:
    depth = 0
    in_quote = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_quote:
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise ParseError("Unbalanced Terraform block")


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts, buf = [], []
    depth = 0
    in_quote = False
    escape = False
    for ch in text:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
        elif not in_quote and ch in "[{(":
            depth += 1
        elif not in_quote and ch in "]})":
            depth -= 1
        if ch == delimiter and depth == 0 and not in_quote:
            item = "".join(buf).strip()
            if item:
                parts.append(item)
            buf = []
        else:
            buf.append(ch)
    item = "".join(buf).strip()
    if item:
        parts.append(item)
    return parts


def _parse_value(value: str) -> Any:
    value = value.strip().rstrip(",")
    if not value:
        return None
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    if value in ("true", "false"):
        return value == "true"
    if value == "null":
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if value.startswith("[") and value.endswith("]"):
        return [_parse_value(item) for item in _split_top_level(value[1:-1])]
    if value.startswith("{") and value.endswith("}"):
        result = {}
        for item in _split_top_level(value[1:-1]):
            if "=" in item:
                key, raw = item.split("=", 1)
            elif ":" in item:
                key, raw = item.split(":", 1)
            else:
                continue
            result[key.strip().strip('"')] = _parse_value(raw)
        return result
    return value


def _parse_block_body(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    i = 0
    while i < len(body):
        while i < len(body) and body[i].isspace():
            i += 1
        if i >= len(body):
            break
        match = re.match(r"([A-Za-z_][\w-]*)", body[i:])
        if not match:
            i += 1
            continue
        key = match.group(1)
        i += len(key)
        while i < len(body) and body[i].isspace():
            i += 1
        labels = []
        while i < len(body) and body[i] == '"':
            end = i + 1
            while end < len(body):
                if body[end] == '"' and body[end - 1] != "\\":
                    break
                end += 1
            labels.append(body[i + 1:end])
            i = end + 1
            while i < len(body) and body[i].isspace():
                i += 1
        if i < len(body) and body[i] == "=":
            i += 1
            start = i
            depth = 0
            in_quote = False
            escape = False
            while i < len(body):
                ch = body[i]
                if escape:
                    escape = False
                elif ch == "\\" and in_quote:
                    escape = True
                elif ch == '"':
                    in_quote = not in_quote
                elif not in_quote and ch in "[{(":
                    depth += 1
                elif not in_quote and ch in "]})":
                    depth -= 1
                elif not in_quote and depth == 0 and ch == "\n":
                    break
                i += 1
            result[key] = _parse_value(body[start:i])
        elif i < len(body) and body[i] == "{":
            end = _matching_brace(body, i)
            nested = _parse_block_body(body[i + 1:end])
            entry = {"labels": labels, **nested} if labels else nested
            result.setdefault(key, []).append(entry)
            i = end + 1
        else:
            while i < len(body) and body[i] != "\n":
                i += 1
    return result


def parse_tf_text(text: str, file_path: str = "main.tf") -> list[ParsedResource]:
    clean = _strip_comments(text)
    pattern = re.compile(r'\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    resources = []
    for match in pattern.finditer(clean):
        start = match.end() - 1
        end = _matching_brace(clean, start)
        resource_type, name = match.group(1), match.group(2)
        config = _parse_block_body(clean[start + 1:end])
        resources.append(
            ParsedResource(
                address=f"{resource_type}.{name}",
                resource_type=resource_type,
                name=name,
                provider=_provider(resource_type),
                configuration=config,
                file_path=file_path,
                line_number=clean.count("\n", 0, match.start()) + 1,
                region=config.get("region") if isinstance(config.get("region"), str) else None,
            )
        )
    return resources


def _walk_plan_module(module: dict[str, Any], file_path: str) -> list[ParsedResource]:
    resources = []
    for item in module.get("resources", []) or []:
        address = item.get("address") or f"{item.get('type', 'resource')}.{item.get('name', 'unknown')}"
        values = item.get("values") or item.get("change", {}).get("after") or {}
        resource_type = item.get("type") or address.split(".")[0]
        provider_name = (item.get("provider_name") or "").split(".")[-1]
        resources.append(
            ParsedResource(
                address=address,
                resource_type=resource_type,
                name=item.get("name") or address.rsplit(".", 1)[-1],
                provider=provider_name or _provider(resource_type),
                configuration=values,
                file_path=file_path,
                region=values.get("region") if isinstance(values, dict) else None,
            )
        )
    for child in module.get("child_modules", []) or []:
        resources.extend(_walk_plan_module(child, file_path))
    return resources


def parse_json_data(data: Any, file_path: str) -> list[ParsedResource]:
    if isinstance(data, dict) and isinstance(data.get("planned_values"), dict):
        return _walk_plan_module(data["planned_values"].get("root_module", {}), file_path)
    if isinstance(data, dict) and isinstance(data.get("values"), dict):
        return _walk_plan_module(data["values"].get("root_module", {}), file_path)
    if isinstance(data, dict) and isinstance(data.get("resource_changes"), list):
        root = {"resources": []}
        for item in data["resource_changes"]:
            root["resources"].append({**item, "values": item.get("change", {}).get("after") or {}})
        return _walk_plan_module(root, file_path)
    if isinstance(data, dict) and isinstance(data.get("resource"), dict):
        resources = []
        for resource_type, named in data["resource"].items():
            for name, config in (named or {}).items():
                resources.append(
                    ParsedResource(
                        address=f"{resource_type}.{name}",
                        resource_type=resource_type,
                        name=name,
                        provider=_provider(resource_type),
                        configuration=config or {},
                        file_path=file_path,
                        region=(config or {}).get("region"),
                    )
                )
        return resources
    return []


def parse_file(path: Path, source_name: str | None = None) -> list[ParsedResource]:
    source_name = source_name or path.name
    if path.suffix.lower() == ".tf":
        return parse_tf_text(path.read_text(encoding="utf-8", errors="replace"), source_name)
    if path.suffix.lower() == ".json" or path.name.endswith(".tf.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in {path.name}: {exc}") from exc
        return parse_json_data(data, source_name)
    raise ParseError(f"Unsupported file type: {path.name}")


def safe_extract_zip(path: Path, destination: Path) -> list[Path]:
    extracted = []
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        validate_zip_members(members)
        for member in members:
            if member.is_dir():
                continue
            target = (destination / member.filename).resolve()
            if destination.resolve() not in target.parents or Path(member.filename).is_absolute():
                raise ParseError("Unsafe ZIP path detected")
            if member.file_size > 8 * 1024 * 1024:
                raise ParseError(f"ZIP member too large: {member.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                output.write(source.read())
            extracted.append(target)
    return extracted


def validate_zip_members(members: list[zipfile.ZipInfo]) -> None:
    files = [member for member in members if not member.is_dir()]
    if len(files) > settings.max_archive_members:
        raise ParseError("ZIP contains too many files")
    if sum(member.file_size for member in files) > settings.max_archive_bytes:
        raise ParseError("ZIP expanded size exceeds the configured limit")
    for member in files:
        unix_mode = member.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            raise ParseError("ZIP symbolic links are not supported")
        if member.flag_bits & 0x1:
            raise ParseError("Encrypted ZIP files are not supported")
        if member.compress_size and member.file_size / member.compress_size > settings.max_archive_ratio:
            raise ParseError("ZIP compression ratio exceeds the configured limit")


def parse_path(path: Path, work_dir: Path | None = None) -> list[ParsedResource]:
    if path.suffix.lower() == ".zip":
        if work_dir is None:
            raise ParseError("A work directory is required for ZIP files")
        resources = []
        for item in safe_extract_zip(path, work_dir):
            if item.suffix.lower() in {".tf", ".json"}:
                try:
                    resources.extend(parse_file(item, item.relative_to(work_dir).as_posix()))
                except ParseError:
                    continue
        return resources
    return parse_file(path)
