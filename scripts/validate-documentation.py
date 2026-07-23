#!/usr/bin/env python3
"""Fail closed when Mealy's checked documentation drifts from public surfaces."""

from __future__ import annotations

import argparse
from collections import defaultdict
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import unquote, urlsplit


CORE_DOCUMENTS = (
    "README.md",
    "ARCHITECTURE.md",
    "REQUIREMENTS.md",
    "SECURITY.md",
    "docs/API.md",
    "docs/CI_CD.md",
    "docs/CLI.md",
    "docs/GETTING_STARTED.md",
    "docs/LINUX_SUPPORT.md",
    "docs/OPERATIONS.md",
    "docs/PRODUCTION_READINESS.md",
    "docs/QUICKSTART.md",
    "docs/RELEASE.md",
    "docs/REQUIREMENTS_COVERAGE.md",
    "docs/TESTING.md",
    "docs/THREAT_MODEL.md",
)
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)|!\[[^\]]*\]\(([^)]+)\)")
ROUTE = re.compile(
    r"\.route\(\s*\"(?P<path>/[^\"]+)\"\s*,(?P<body>.*?)"
    r"(?=\n\s*\.(?:route|fallback|method_not_allowed_fallback|layer)|\n\s*\);)",
    re.DOTALL,
)
METHOD = re.compile(r"\b(get|post|put|patch|delete)\s*\(")
DOCUMENTED_ENDPOINT = re.compile(
    r"`(?P<method>GET|POST|PUT|PATCH|DELETE)(?:`\s*\|\s*`|\s+)"
    r"(?P<path>/[^`|\s]+)`"
)
DOCUMENTED_ENDPOINT_ROW = re.compile(
    r"^\|\s*`(?P<method>GET|POST|PUT|PATCH|DELETE)`\s*\|\s*"
    r"`(?P<path>/[^`|\s]+)`\s*\|",
    re.MULTILINE,
)
COMMAND_LINE = re.compile(r"^\s{2}([a-z][a-z0-9-]*)\s{2,}\S")
DOCUMENTED_COMMAND = re.compile(
    r"^\| `(?P<command>[a-z][a-z0-9-]*)` \| (?P<purpose>[^|]*\S[^|]*) \|$",
    re.MULTILINE,
)
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```+|~~~+)")
MAX_PACKAGED_MARKDOWN_FILES = 256
MAX_PACKAGED_MARKDOWN_BYTES = 16 * 1024 * 1024


class DocumentationError(RuntimeError):
    """One or more checked documentation contracts failed."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the script's parent repository)",
    )
    parser.add_argument(
        "--cli",
        type=Path,
        required=True,
        help="built mealyctl executable whose public command surface is authoritative",
    )
    parser.add_argument(
        "--mode",
        choices=("source", "package"),
        default="source",
        help=(
            "validate a Git source checkout exactly, or validate the self-contained "
            "documentation and CLI in an extracted release package"
        ),
    )
    return parser.parse_args()


def read_text(path: Path) -> str:
    try:
        body = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise DocumentationError(f"cannot read UTF-8 documentation input {path}: {error}") from error
    if not body.strip():
        raise DocumentationError(f"documentation input is empty: {path}")
    return body


def tracked_markdown(repository: Path) -> list[Path]:
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                "*.md",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise DocumentationError(f"cannot enumerate tracked Markdown: {error}") from error
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeError as error:
            raise DocumentationError("tracked Markdown path is not UTF-8") from error
        path = repository / relative
        if not path.is_file() or path.is_symlink():
            raise DocumentationError(f"tracked Markdown is not a regular file: {relative}")
        paths.append(path)
    if not paths:
        raise DocumentationError("repository contains no tracked Markdown")
    return sorted(paths)


def packaged_markdown(repository: Path) -> list[Path]:
    paths: list[Path] = []
    total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise DocumentationError(f"cannot enumerate packaged Markdown: {error}")

    for current, directories, files in os.walk(
        repository, topdown=True, onerror=walk_error, followlinks=False
    ):
        current_path = Path(current)
        for directory in directories:
            candidate = current_path / directory
            if candidate.is_symlink():
                relative = candidate.relative_to(repository)
                raise DocumentationError(f"package contains a symlink directory: {relative}")
        for name in files:
            if not name.endswith(".md"):
                continue
            path = current_path / name
            relative = path.relative_to(repository)
            try:
                metadata = path.lstat()
            except OSError as error:
                raise DocumentationError(
                    f"cannot inspect packaged Markdown {relative}: {error}"
                ) from error
            if not stat.S_ISREG(metadata.st_mode):
                raise DocumentationError(
                    f"packaged Markdown is not a regular file: {relative}"
                )
            paths.append(path)
            total_bytes += metadata.st_size
            if len(paths) > MAX_PACKAGED_MARKDOWN_FILES:
                raise DocumentationError(
                    "package exceeds the 256-file Markdown inventory bound"
                )
            if total_bytes > MAX_PACKAGED_MARKDOWN_BYTES:
                raise DocumentationError(
                    "package exceeds the 16 MiB Markdown content bound"
                )
    if not paths:
        raise DocumentationError("package contains no Markdown")
    return sorted(paths)


def markdown_lines_without_fences(body: str):
    fence: str | None = None
    for line in body.splitlines():
        marker = FENCE.match(line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token[0]
            elif token[0] == fence:
                fence = None
            continue
        if fence is None:
            yield line


def github_slug(heading: str) -> str:
    heading = re.sub(r"<[^>]*>", "", heading)
    heading = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
    heading = heading.replace("`", "").strip().lower()
    heading = re.sub(r"[^\w\- ]", "", heading, flags=re.UNICODE)
    return re.sub(r"\s", "-", heading)


def anchors(body: str) -> set[str]:
    seen: dict[str, int] = defaultdict(int)
    result: set[str] = set()
    for line in markdown_lines_without_fences(body):
        match = HEADING.match(line)
        if match is None:
            continue
        base = github_slug(match.group(1))
        if not base:
            continue
        number = seen[base]
        seen[base] += 1
        result.add(base if number == 0 else f"{base}-{number}")
    return result


def link_destination(raw: str) -> str | None:
    raw = raw.strip()
    if raw.startswith("<"):
        end = raw.find(">")
        return raw[1:end] if end >= 1 else None
    return raw.split(maxsplit=1)[0] if raw else None


def validate_local_links(repository: Path, markdown: list[Path]) -> int:
    anchor_cache: dict[Path, set[str]] = {}
    failures: list[str] = []
    checked = 0
    for source in markdown:
        body = read_text(source)
        relative_source = source.relative_to(repository)
        for line in markdown_lines_without_fences(body):
            line = re.sub(r"`[^`]*`", "", line)
            for match in LINK.finditer(line):
                destination = link_destination(match.group(1) or match.group(2))
                if destination is None:
                    failures.append(f"{relative_source}: malformed Markdown destination")
                    continue
                split = urlsplit(destination)
                if split.scheme or split.netloc:
                    continue
                decoded_path = unquote(split.path)
                target = source if not decoded_path else source.parent / decoded_path
                try:
                    target = target.resolve(strict=True)
                except OSError:
                    failures.append(f"{relative_source}: missing local target {destination}")
                    continue
                try:
                    target.relative_to(repository)
                except ValueError:
                    failures.append(f"{relative_source}: local link escapes repository: {destination}")
                    continue
                checked += 1
                if not split.fragment or target.is_dir():
                    continue
                if target.suffix.lower() != ".md":
                    failures.append(f"{relative_source}: fragment targets non-Markdown file: {destination}")
                    continue
                if target not in anchor_cache:
                    anchor_cache[target] = anchors(read_text(target))
                fragment = unquote(split.fragment).lower()
                if fragment not in anchor_cache[target]:
                    failures.append(f"{relative_source}: missing local fragment {destination}")
    if failures:
        raise DocumentationError("\n".join(failures))
    return checked


def registered_endpoints(api_source: str) -> set[tuple[str, str]]:
    endpoints: set[tuple[str, str]] = set()
    for route in ROUTE.finditer(api_source):
        methods = set(METHOD.findall(route.group("body")))
        if not methods:
            raise DocumentationError(f"cannot determine method for registered route {route.group('path')}")
        endpoints.update((method.upper(), route.group("path")) for method in methods)
    if len(endpoints) < 60:
        raise DocumentationError(f"implausibly small registered API surface: {len(endpoints)} endpoints")
    return endpoints


def documented_endpoint_rows(api_document: str) -> list[tuple[str, str]]:
    return [
        (match.group("method"), match.group("path"))
        for match in DOCUMENTED_ENDPOINT.finditer(api_document)
    ]


def documented_endpoints(api_document: str) -> set[tuple[str, str]]:
    endpoints = set(documented_endpoint_rows(api_document))
    table_rows = [
        (match.group("method"), match.group("path"))
        for match in DOCUMENTED_ENDPOINT_ROW.finditer(api_document)
    ]
    duplicates = sorted(
        endpoint for endpoint in set(table_rows) if table_rows.count(endpoint) != 1
    )
    if duplicates:
        raise DocumentationError(
            "API.md duplicates endpoint rows: "
            + ", ".join(f"{method} {path}" for method, path in duplicates)
        )
    if len(endpoints) < 60:
        raise DocumentationError(
            f"implausibly small documented API surface: {len(endpoints)} endpoints"
        )
    return endpoints


def validate_api_contract(repository: Path) -> int:
    registered = registered_endpoints(read_text(repository / "crates/mealy-api/src/lib.rs"))
    documented = documented_endpoints(read_text(repository / "docs/API.md"))
    missing = sorted(registered - documented)
    stale = sorted(documented - registered)
    if missing or stale:
        details = []
        details.extend(f"API.md missing registered endpoint: {method} {path}" for method, path in missing)
        details.extend(f"API.md names unregistered endpoint: {method} {path}" for method, path in stale)
        raise DocumentationError("\n".join(details))
    return len(registered)


def validate_packaged_api_contract(repository: Path) -> int:
    return len(documented_endpoints(read_text(repository / "docs/API.md")))


def public_commands(cli: Path) -> set[str]:
    try:
        result = subprocess.run(
            [str(cli.resolve(strict=True)), "--help"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DocumentationError(f"cannot inspect mealyctl public commands: {error}") from error
    commands = {match.group(1) for line in result.stdout.splitlines() if (match := COMMAND_LINE.match(line))}
    commands.discard("help")
    if len(commands) < 20:
        raise DocumentationError(f"implausibly small public CLI surface: {len(commands)} commands")
    return commands


def validate_usage_contract(repository: Path, cli: Path) -> int:
    commands = public_commands(cli)
    rows = [
        match.group("command")
        for match in DOCUMENTED_COMMAND.finditer(read_text(repository / "docs/CLI.md"))
    ]
    documented = set(rows)
    missing = sorted(commands - documented)
    stale = sorted(documented - commands)
    duplicates = sorted(command for command in documented if rows.count(command) != 1)
    if missing or stale or duplicates:
        details = []
        if missing:
            details.append("CLI.md omits public commands: " + ", ".join(missing))
        if stale:
            details.append("CLI.md names non-public commands: " + ", ".join(stale))
        if duplicates:
            details.append("CLI.md duplicates command rows: " + ", ".join(duplicates))
        raise DocumentationError("\n".join(details))
    return len(commands)


def main() -> int:
    arguments = parse_arguments()
    repository = arguments.repository.resolve(strict=True)
    for relative in CORE_DOCUMENTS:
        path = repository / relative
        if not path.is_file() or path.is_symlink():
            raise DocumentationError(f"required documentation is absent or not a regular file: {relative}")
        read_text(path)
    markdown = (
        tracked_markdown(repository)
        if arguments.mode == "source"
        else packaged_markdown(repository)
    )
    link_count = validate_local_links(repository, markdown)
    endpoint_count = (
        validate_api_contract(repository)
        if arguments.mode == "source"
        else validate_packaged_api_contract(repository)
    )
    command_count = validate_usage_contract(repository, arguments.cli)
    print(
        "documentation contract: ok "
        f"({len(markdown)} Markdown files, {link_count} local links, "
        f"{endpoint_count} API endpoints, {command_count} public CLI commands)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DocumentationError as error:
        print(f"documentation contract failed: {error}", file=sys.stderr)
        raise SystemExit(65) from error
