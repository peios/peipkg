#!/usr/bin/env python3
"""Reject ambiguous/retired resolver citations; optionally check learn targets."""

import argparse
from pathlib import Path
import re
import sys


BOOKS = {
    "PSPU": "200--pcsa.shelf/400--pspu.book",
    "peipkg TRM": "300--trms.shelf/500--peipkg.book",
}
# Current articles have chapter.article identifiers. Qualify every citation:
# the retired specification reused numbers now belonging to different books.
CITATION = re.compile(r"(PSPU|peipkg TRM) §([1-9][0-9]*)\.([1-9][0-9]*)(?![0-9]|\.[0-9])")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--learn", type=Path, help="also verify article paths in this learn checkout")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = sorted((root / "internal/resolver").rglob("*.go"))
    if not paths:
        parser.error("no resolver Go sources found")
    errors = []
    citations = set()
    count = 0
    for path in paths:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            matches = list(CITATION.finditer(line))
            qualified = {line.index("§", match.start(), match.end()) for match in matches}
            for marker in re.finditer("§", line):
                if marker.start() not in qualified:
                    errors.append(f"{path.relative_to(root)}:{number}: unqualified or obsolete citation: {line.strip()}")
            citations.update(match.groups() for match in matches)
            count += len(matches)
    if args.learn:
        shelf = args.learn / "peios.product/3--advanced-peios.antho"
        for book, chapter, article in sorted(citations):
            matches = list((shelf / BOOKS[book]).glob(f"{chapter}--*/{article}--*.md"))
            if len(matches) != 1:
                errors.append(f"{book} §{chapter}.{article}: expected one learn article, found {len(matches)}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Resolver citations: {count} qualified references to {len(citations)} articles"
          + ("; all learn targets exist" if args.learn else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
