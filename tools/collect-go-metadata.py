#!/usr/bin/env python3
"""Collect the exact Go source and licence closure used by command packages.

The script consumes ``go list -deps -json`` rather than copying the complete
vendor tree.  That keeps the debugsource package tied to files that the Go
compiler could actually mention and makes a missing module licence a hard
packaging failure instead of silently publishing an incomplete notice set.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys


SOURCE_FIELDS = (
    "GoFiles",
    "CgoFiles",
    "CFiles",
    "CXXFiles",
    "MFiles",
    "HFiles",
    "FFiles",
    "SFiles",
    "SysoFiles",
    "SwigFiles",
    "SwigCXXFiles",
    "EmbedFiles",
)
LICENCE_NAMES = ("license", "licence", "copying", "notice")


def records(raw: str):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            return
        value, offset = decoder.raw_decode(raw, offset)
        yield value


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe package path: {value!r}")
    return path


def copy_unique(source: Path, destination: Path) -> None:
    if destination.exists():
        if destination.read_bytes() != source.read_bytes():
            raise RuntimeError(f"source collision at {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def module_root(module: dict, package_dir: Path, import_path: str) -> Path:
    replacement = module.get("Replace")
    if replacement and replacement.get("Dir"):
        return Path(replacement["Dir"])
    if module.get("Dir"):
        return Path(module["Dir"])

    # In vendor mode Go does not always expose Module.Dir.  Derive the root
    # from the package import path and directory, then verify the result.
    module_path = module["Path"]
    if import_path == module_path:
        return package_dir
    prefix = module_path + "/"
    if not import_path.startswith(prefix):
        raise RuntimeError(
            f"package {import_path} is not below its module {module_path}"
        )
    suffix = PurePosixPath(import_path[len(prefix) :])
    root = package_dir
    for _ in suffix.parts:
        root = root.parent
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-root", required=True, type=Path)
    parser.add_argument("--licence-root", required=True, type=Path)
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()

    proc = subprocess.run(
        ["go", "list", "-deps", "-json", *args.packages],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    packages = list(records(proc.stdout))
    args.debug_root.mkdir(parents=True, exist_ok=True)
    args.licence_root.mkdir(parents=True, exist_ok=True)

    modules: dict[str, tuple[dict, Path, str]] = {}
    for package in packages:
        import_path = package.get("ImportPath")
        directory = package.get("Dir")
        if not import_path or not directory or import_path in ("C", "unsafe"):
            continue
        relative_import = safe_relative(import_path)
        source_dir = Path(directory)
        for field in SOURCE_FIELDS:
            for name in package.get(field, []):
                relative_name = safe_relative(name)
                source = source_dir / relative_name
                if not source.is_file():
                    raise RuntimeError(f"listed Go source is missing: {source}")
                copy_unique(source, args.debug_root / relative_import / relative_name)

        module = package.get("Module")
        if module and not module.get("Main") and module.get("Path"):
            modules.setdefault(module["Path"], (module, source_dir, import_path))

    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    # Peios deliberately splits the toolchain sources from the executable
    # GOROOT. Its canonical package licence therefore lives under
    # /usr/share/licenses even though upstream binary archives put it at the
    # GOROOT top level. Accept only those two explicit layouts.
    go_licence = next(
        (
            candidate
            for candidate in (
                goroot / "LICENSE",
                Path("/usr/share/licenses/org.golang.go/LICENSE"),
            )
            if candidate.is_file()
        ),
        None,
    )
    if go_licence is None:
        raise RuntimeError("Go toolchain licence is missing from its recognized package locations")
    copy_unique(go_licence, args.licence_root / "go" / "LICENSE")

    missing: list[tuple[str, str]] = []
    for module_path, (module, package_dir, import_path) in sorted(modules.items()):
        root = module_root(module, package_dir, import_path)
        found = []
        for current, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                lower = name.lower()
                if lower.startswith(LICENCE_NAMES):
                    found.append(Path(current) / name)
        if not found:
            missing.append((module_path, module.get("Version", "unknown")))
            continue
        destination_root = args.licence_root / safe_relative(module_path)
        for source in found:
            copy_unique(source, destination_root / source.relative_to(root))

    if missing:
        print("missing distributable licence text for Go module(s):", file=sys.stderr)
        for module_path, version in missing:
            print(f"  {module_path} {version}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
