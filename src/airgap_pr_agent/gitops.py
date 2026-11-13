"""Git diff parsing and robust file reading."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(Exception):
    pass


@dataclass(frozen=True)
class DiffRefs:
    base: str
    head: str


@dataclass
class ChangedFile:
    path: str
    old_path: str | None
    added: dict[int, str]
    source: str


def _git(repo: Path, *args: str) -> bytes:
    r = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args], cwd=repo, capture_output=True
    )
    if r.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} failed: {r.stderr.decode('utf-8', 'replace').strip()}"
        )
    return r.stdout


def decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "gb18030"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1")


def read_at(repo: Path, rev: str, path: str) -> str:
    return decode(_git(repo, "show", f"{rev}:{path}"))


def merge_base(repo: Path, a: str, b: str) -> str:
    return _git(repo, "merge-base", a, b).decode().strip()


def tracked_files(repo: Path) -> list[str]:
    out = _git(repo, "ls-files", "-z").decode("utf-8", "replace")
    return [p for p in out.split("\0") if p]


def whole_files(repo: Path, paths: list[str]) -> list[ChangedFile]:
    result = []
    for p in paths:
        data = (repo / p).read_bytes()
        if b"\0" in data:
            continue
        source = decode(data)
        added = {i: line for i, line in enumerate(source.splitlines(), 1)}
        result.append(ChangedFile(p, None, added, source))
    return result


def _binary_paths(repo: Path, refs: DiffRefs) -> set[str]:
    out = _git(
        repo, "diff", "--numstat", "-z", "--find-renames", "--diff-filter=AMR",
        refs.base, refs.head,
    ).decode("utf-8", "replace")
    parts = out.split("\0")
    binary: set[str] = set()
    i = 0
    while i < len(parts):
        rec = parts[i]
        i += 1
        if not rec:
            continue
        fields = rec.split("\t", 2)
        if len(fields) < 3:
            continue
        add, _, name = fields
        if name == "":  # rename: next two NUL-separated entries are old, new
            new = parts[i + 1] if i + 1 < len(parts) else ""
            i += 2
            name = new
        if add == "-":
            binary.add(name)
    return binary


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_files(repo: Path, refs: DiffRefs) -> list[ChangedFile]:
    diff = _git(
        repo, "diff", "--no-color", "--unified=0", "--find-renames",
        "--diff-filter=AMR", refs.base, refs.head,
    ).decode("utf-8", "replace")
    binary = _binary_paths(repo, refs)

    entries: list[dict] = []
    cur: dict | None = None
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            cur = {"old": None, "path": None, "lines": []}
            entries.append(cur)
        elif cur is None:
            continue
        elif line.startswith("rename from "):
            cur["old"] = line[len("rename from "):]
        elif line.startswith("+++ b/"):
            cur["path"] = line[len("+++ b/"):]
        elif line.startswith("rename to "):
            cur["path"] = cur["path"] or line[len("rename to "):]
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            if m:
                start = int(m.group(1))
                count = 1 if m.group(2) is None else int(m.group(2))
                cur["lines"].extend(range(start, start + count))

    result = []
    for e in entries:
        path = e["path"]
        if path is None or path in binary:
            continue
        source = read_at(repo, refs.head, path)
        text = source.splitlines()
        added = {n: text[n - 1] for n in e["lines"] if 0 < n <= len(text)}
        result.append(ChangedFile(path, e["old"], added, source))
    return result
