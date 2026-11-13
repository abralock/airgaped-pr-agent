import os
import shutil
import subprocess
from pathlib import Path

import pytest


def pytest_runtest_setup(item):
    if item.get_closest_marker("requires_gitleaks") is None:
        return
    if shutil.which(os.environ.get("GITLEAKS_BIN", "gitleaks")) is None:
        msg = "gitleaks binary not found"
        if os.environ.get("PR_AGENT_REQUIRE_GITLEAKS") == "1":
            pytest.fail(msg)
        pytest.skip(msg)


class GitRepo:
    def __init__(self, path: Path):
        self.path = path

    def git(self, *args: str) -> str:
        r = subprocess.run(
            ["git", *args], cwd=self.path, capture_output=True, check=True
        )
        return r.stdout.decode("utf-8", "replace").strip()

    def commit(self, files: dict[str, str | bytes | None], msg: str = "c") -> str:
        for name, content in files.items():
            target = self.path / name
            if content is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                target.write_bytes(content.encode("utf-8"))
            else:
                target.write_bytes(content)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def branch(self, name: str) -> None:
        self.git("checkout", "-q", "-b", name)


@pytest.fixture
def git_repo(tmp_path):
    repo = GitRepo(tmp_path)
    repo.git("init", "-q", "-b", "main")
    repo.git("config", "user.name", "Test")
    repo.git("config", "user.email", "test@example.com")
    repo.git("config", "commit.gpgsign", "false")
    return repo
