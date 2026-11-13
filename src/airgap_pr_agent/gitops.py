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


_GITLINK = "160000"  # a submodule: the tree holds a commit id, not file content


def tracked_files(repo: Path) -> list[str]:
    """Tracked paths, without submodules."""
    out = _git(repo, "ls-files", "--stage", "-z").decode("utf-8", "replace")
    paths = []
    for rec in out.split("\0"):
        meta, sep, path = rec.partition("\t")
        if sep and meta.split(" ", 1)[0] != _GITLINK:
            paths.append(path)
    return paths


def whole_files(repo: Path, paths: list[str]) -> list[ChangedFile]:
    result = []
    for p in paths:
        target = repo / p
        if not target.is_file():  # e.g. a submodule checkout directory
            continue
        data = target.read_bytes()
        if b"\0" in data:
            continue
        source = decode(data)
        added = {i: line for i, line in enumerate(source.splitlines(), 1)}
        result.append(ChangedFile(p, None, added, source))
    return result


def _numstat(repo: Path, refs: DiffRefs) -> list[tuple[str, str | None, bool]]:
    """(path, old_path, is_binary) per changed file, in diff order; NUL-safe."""
    out = _git(
        repo, "diff", "--numstat", "-z", "--find-renames", "--diff-filter=AMR",
        refs.base, refs.head,
    ).decode("utf-8", "replace")
    parts = out.split("\0")
    entries: list[tuple[str, str | None, bool]] = []
    i = 0
    while i < len(parts):
        rec = parts[i]
        i += 1
        fields = rec.split("\t", 2)
        if len(fields) < 3:
            continue
        add, _, name = fields
        old = None
        if name == "":  # rename: next two NUL-separated entries are old, new
            old, name = parts[i], parts[i + 1]
            i += 2
        entries.append((name, old, add == "-"))
    return entries


def _gitlinks(repo: Path, refs: DiffRefs) -> set[str]:
    """New-side paths of changed entries that are submodules (mode 160000)."""
    out = _git(
        repo, "diff", "--raw", "-z", "--find-renames", "--diff-filter=AMR",
        refs.base, refs.head,
    ).decode("utf-8", "replace")
    parts = out.split("\0")
    links: set[str] = set()
    i = 0
    while i < len(parts):
        meta = parts[i]
        i += 1
        if not meta.startswith(":"):
            continue
        fields = meta[1:].split(" ")
        if len(fields) < 5:
            continue
        n_paths = 2 if fields[4][:1] in ("R", "C") else 1
        path = parts[i + n_paths - 1] if i + n_paths - 1 < len(parts) else ""
        i += n_paths
        if fields[1] == _GITLINK:
            links.add(path)
    return links


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_files(repo: Path, refs: DiffRefs) -> list[ChangedFile]:
    diff = _git(
        repo, "diff", "--no-color", "--unified=0", "--find-renames",
        "--diff-filter=AMR", refs.base, refs.head,
    ).decode("utf-8", "replace")
    # Paths come from the NUL-separated numstat; the diff text is used only for
    # hunks, matched to files by order (one "diff --git" block per file).
    entries = _numstat(repo, refs)
    hunks: list[list[int]] = []
    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            hunks.append([])
        elif line.startswith("@@") and hunks:
            m = _HUNK.match(line)
            if m:
                start = int(m.group(1))
                count = 1 if m.group(2) is None else int(m.group(2))
                hunks[-1].extend(range(start, start + count))
    if len(hunks) != len(entries):
        raise GitError("diff and numstat disagree on changed files")

    gitlinks = _gitlinks(repo, refs)
    result = []
    for (path, old, is_binary), lines in zip(entries, hunks):
        if is_binary or path in gitlinks:
            continue
        source = read_at(repo, refs.head, path)
        text = source.splitlines()
        added = {n: text[n - 1] for n in lines if 0 < n <= len(text)}
        result.append(ChangedFile(path, old, added, source))
    return result
