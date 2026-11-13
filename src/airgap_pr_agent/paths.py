from __future__ import annotations

import pathspec


class PathFilter:
    def __init__(self, include: list[str], exclude: list[str]) -> None:
        self._include = pathspec.PathSpec.from_lines("gitwildmatch", include)
        self._exclude = pathspec.PathSpec.from_lines("gitwildmatch", exclude)

    def allows(self, path: str) -> bool:
        return self._include.match_file(path) and not self._exclude.match_file(path)

    @classmethod
    def from_globs(
        cls, include: list[str], exclude: list[str], extra_exclude: list[str] | None = None
    ) -> "PathFilter":
        return cls(include, [*exclude, *(extra_exclude or [])])
