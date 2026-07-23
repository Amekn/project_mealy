#!/usr/bin/env python3
"""Archived v0.1.0 deterministic macOS conversation-only preview packager."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TARGETS = {"macos-arm64-preview", "macos-x86_64-preview"}
HOST_PATH = re.compile(
    rb"/(?:home|Users)/[^/\x00-\x1f]+/|/root/|[A-Za-z]:[/\\]Users[/\\]"
)
RELEASE_DOCUMENTS = (
    "API.md",
    "CI_CD.md",
    "CLI.md",
    "DOMAIN_MODEL.md",
    "IMPLEMENTATION_PLAN.md",
    "OPERATIONS.md",
    "PRODUCTION_READINESS.md",
    "QUICKSTART.md",
    "README.md",
    "RELEASE.md",
    "REQUIREMENTS_COVERAGE.md",
    "TESTING.md",
    "THREAT_MODEL.md",
    "benchmarks/2026-07-12-development-soak.json",
    "benchmarks/2026-07-13-debian-13-installed-package-smoke.md",
    "benchmarks/2026-07-13-development-soak.json",
    "benchmarks/2026-07-13-five-minute-paced-soak.json",
    "benchmarks/2026-07-13-live-public-web-fetch.md",
    "benchmarks/2026-07-13-schema14-long-soak-failure.md",
    "benchmarks/2026-07-13-storage-optimized-soak.json",
    "benchmarks/2026-07-13-supply-chain-policy-audit.md",
    "benchmarks/2026-07-13-thirty-minute-paced-soak.json",
    "benchmarks/2026-07-13-ubuntu-24.04-installed-package-smoke.md",
    "benchmarks/2026-07-14-nine-hour-supervisor-interruption.md",
    "benchmarks/2026-07-15-fedora-44-installed-package-smoke.md",
    "benchmarks/2026-07-16-schema15-long-soak-contention-failure.md",
    "benchmarks/2026-07-16-schema15-release-soak-lineage.json",
    "benchmarks/2026-07-16-schema15-release-soak.json",
    "benchmarks/2026-07-20-schema15-near-deadline-provider-dispatch-failure.md",
    "benchmarks/2026-07-20-interrupted-soak-and-storage-architecture.md",
    "benchmarks/README.md",
    "benchmarks/release-soak.json",
    "benchmarks/release-soak-subject.json",
    "decisions/0001-modular-monolith-and-workers.md",
    "decisions/0002-transactional-journal.md",
    "decisions/0003-effect-recovery.md",
    "decisions/0004-security-boundaries.md",
    "decisions/0005-durable-session-inbox.md",
    "decisions/0006-context-and-memory.md",
    "decisions/0007-local-api.md",
    "decisions/0008-risk-based-validation.md",
    "decisions/0009-sqlite-writer-and-snapshot-readers.md",
    "decisions/README.md",
    "research/GAP_MATRIX.md",
    "research/REFERENCE_SYSTEMS.md",
)
PACKAGE_FILES = (
    "LICENSE",
    "ARCHITECTURE.md",
    "README.md",
    "REQUIREMENTS.md",
    "SECURITY.md",
    *(f"docs/{document}" for document in RELEASE_DOCUMENTS),
)


class BuildError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise BuildError(message)


def regular_file(path: Path, executable: bool = False) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"required input is absent: {path}")
    if not stat.S_ISREG(mode):
        fail(f"required input is not a real file: {path}")
    if executable and mode & 0o111 == 0:
        fail(f"required input is not executable: {path}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_identity(binary: Path, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"release binary identity check failed: {binary.name}: {error}")
    if result.stderr:
        fail(f"release binary identity check wrote stderr: {binary.name}")
    return result.stdout.rstrip("\n")


def walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)


def normalize_sbom(
    raw_path: Path, version: str, target: str, commit: str, epoch: int
) -> bytes:
    regular_file(raw_path)
    if raw_path.stat().st_size > 16 * 1024 * 1024:
        fail("raw CycloneDX SBOM exceeds the 16 MiB bound")
    try:
        value = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"raw CycloneDX SBOM is invalid: {error}")
    components = value.get("components") if isinstance(value, dict) else None
    if (
        value.get("bomFormat") != "CycloneDX"
        or not isinstance(value.get("specVersion"), str)
        or not isinstance(value.get("version"), int)
        or not isinstance(components, list)
        or not components
    ):
        fail("raw CycloneDX SBOM is incomplete")

    identity = hashlib.sha256(
        f"mealy.release.sbom.v1|{version}|{target}|{commit}\n".encode()
    ).hexdigest()
    uuid = (
        f"{identity[:8]}-{identity[8:12]}-5{identity[13:16]}-"
        f"8{identity[17:20]}-{identity[20:32]}"
    )
    from datetime import datetime, timezone

    value["serialNumber"] = f"urn:uuid:{uuid}"
    metadata = value.setdefault("metadata", {})
    metadata["timestamp"] = datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    metadata["component"] = {
        "bom-ref": f"mealy-release:{version}:{target}:{commit}",
        "type": "application",
        "group": "Amekn",
        "name": "mealy",
        "version": version,
        "properties": [
            {"name": "mealy:release:commit", "value": commit},
            {"name": "mealy:release:target", "value": target},
        ],
    }
    for component in components:
        if not isinstance(component, dict):
            fail("raw CycloneDX component is invalid")
        name = component.get("name")
        if component.get("type") == "file" and isinstance(name, str):
            if name.endswith("/bin/mealyd"):
                component["name"] = "/bin/mealyd"
            elif name.endswith("/bin/mealyctl"):
                component["name"] = "/bin/mealyctl"
        properties = component.get("properties")
        if isinstance(properties, list):
            properties.sort(key=lambda item: (item.get("name", ""), item.get("value", "")))
    components.sort(key=lambda item: item.get("bom-ref", ""))
    dependencies = value.get("dependencies")
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, dict) and isinstance(dependency.get("dependsOn"), list):
                dependency["dependsOn"].sort()
        dependencies.sort(key=lambda item: item.get("ref", ""))
    if any(
        re.match(r"^/(?:home|Users|tmp|private/tmp|github)/", item)
        for item in walk_strings(value)
    ):
        fail("normalized CycloneDX SBOM retains a local build path")
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def add_tar_entry(archive: tarfile.TarFile, source: Path, name: str, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    if source.is_dir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        archive.addfile(info)
        return
    data = source.read_bytes()
    info.size = len(data)
    info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
    import io

    archive.addfile(info, io.BytesIO(data))


def main(arguments: list[str]) -> int:
    if len(arguments) != 9:
        fail(
            "usage: build-macos-preview.py VERSION TARGET BINARY_DIR RAW_SBOM "
            "THIRD_PARTY_LICENSES OUTPUT_DIR COMMIT SOURCE_DATE_EPOCH STATE_SCHEMA_VERSION"
        )
    version, target, binary_text, raw_sbom_text, licenses_text, output_text, commit, epoch_text, schema_text = arguments
    if not VERSION.fullmatch(version) or target not in TARGETS or not COMMIT.fullmatch(commit):
        fail("macOS preview release identity is invalid")
    try:
        epoch = int(epoch_text)
        schema = int(schema_text)
    except ValueError:
        fail("macOS preview numeric identity is invalid")
    if epoch < 1 or not 1 <= schema <= 9999:
        fail("macOS preview numeric identity is outside its bound")

    repository = Path(__file__).resolve().parent.parent
    docs_root = repository / "docs"
    document_entries = tuple(docs_root.rglob("*"))
    actual_documents = tuple(
        sorted(
            path.relative_to(docs_root).as_posix()
            for path in document_entries
            if path.is_file() and not path.is_symlink()
        )
    )
    if (
        actual_documents != tuple(sorted(RELEASE_DOCUMENTS))
        or any(
            path.is_symlink() or (not path.is_file() and not path.is_dir())
            for path in document_entries
        )
    ):
        fail("macOS release documentation inventory is incomplete or unsupported")
    binary_dir = Path(binary_text).resolve()
    raw_sbom = Path(raw_sbom_text).resolve()
    licenses = Path(licenses_text).resolve()
    output = Path(output_text).resolve()
    if output.exists() and (output.is_symlink() or not output.is_dir()):
        fail("macOS preview output must be a real directory")
    output.mkdir(parents=True, exist_ok=True)

    binaries: dict[str, Path] = {}
    for name in ("mealyd", "mealyctl"):
        binary = binary_dir / name
        regular_file(binary, executable=True)
        if run_identity(binary, ["--version"]) != f"{name} {version}":
            fail(f"release binary version does not match package identity: {name}")
        if HOST_PATH.search(binary.read_bytes()):
            fail(f"release binary contains a host-specific user-home path: {name}")
        binaries[name] = binary
    if run_identity(binaries["mealyd"], ["--print-supported-schema-version"]) != str(schema):
        fail("mealyd state-schema support does not match package identity")

    regular_file(licenses)
    license_bytes = licenses.read_bytes()
    if not 1024 <= len(license_bytes) <= 8 * 1024 * 1024:
        fail("third-party license notice is outside its package bound")
    lowered = license_bytes.lower()
    if b"<h1>mealy third-party licenses</h1>" not in lowered or any(
        marker in lowered
        for marker in (b"<script", b"<iframe", b"javascript:", b"/home/", b"target/")
    ):
        fail("third-party license notice is invalid")

    normalized_sbom = normalize_sbom(raw_sbom, version, target, commit, epoch)
    package_name = f"mealy-v{version}-{target}"
    with tempfile.TemporaryDirectory(prefix="mealy-macos-preview.") as temporary_text:
        root = Path(temporary_text) / package_name
        (root / "bin").mkdir(parents=True)
        for name, source in binaries.items():
            shutil.copyfile(source, root / "bin" / name)
            (root / "bin" / name).chmod(0o755)
        for logical in PACKAGE_FILES:
            source = repository / logical
            regular_file(source)
            destination = root / logical
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
        (root / "THIRD-PARTY-LICENSES.html").write_bytes(license_bytes)
        (root / "SBOM.cdx.json").write_bytes(normalized_sbom)
        manifest = {
            "schemaVersion": "mealy.macos-preview.v1",
            "version": version,
            "target": target,
            "commit": commit,
            "sourceDateEpoch": epoch,
            "stateSchemaVersion": schema,
            "capabilityBoundary": "conversation-only-control-plane-preview",
            "sbom": "SBOM.cdx.json",
            "licenses": "THIRD-PARTY-LICENSES.html",
        }
        (root / "BUILD-MANIFEST.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        payload_files = sorted(path for path in root.rglob("*") if path.is_file())
        payload = "".join(f"{sha256(path)}  {path.relative_to(root)}\n" for path in payload_files)
        (root / "PAYLOAD-SHA256SUMS").write_text(payload, encoding="ascii")
        for path in root.rglob("*"):
            os.utime(path, (epoch, epoch), follow_symlinks=False)

        archive_path = output / f"{package_name}.tar.gz"
        with archive_path.open("wb") as raw_archive:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_archive, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    entries = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
                    for entry in entries:
                        relative = entry.relative_to(root)
                        name = package_name if relative == Path(".") else f"{package_name}/{relative.as_posix()}"
                        add_tar_entry(archive, entry, name, epoch)
        archive_path.chmod(0o644)
        sbom_path = output / f"{package_name}.cdx.json"
        sbom_path.write_bytes(normalized_sbom)
        sbom_path.chmod(0o644)
        checksum_path = output / f"SHA256SUMS-{target}"
        assets = sorted((archive_path, sbom_path), key=lambda path: path.name)
        checksum_path.write_text(
            "".join(f"{sha256(path)}  {path.name}\n" for path in assets), encoding="ascii"
        )
        checksum_path.chmod(0o644)
        print(archive_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BuildError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(65) from error
