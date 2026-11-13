from airgap_pr_agent.gitops import (
    DiffRefs, changed_files, decode, merge_base, read_at, tracked_files, whole_files,
)


def test_added_lines_use_head_numbering(git_repo):
    base = git_repo.commit({"a.py": "x = 1\ny = 2\n"})
    head = git_repo.commit({"a.py": "x = 1\nz = 3\ny = 2\n", "b.py": "print(1)\n"})
    files = {f.path: f for f in changed_files(git_repo.path, DiffRefs(base, head))}
    assert files["a.py"].added == {2: "z = 3"}
    assert files["b.py"].added == {1: "print(1)"}
    assert files["a.py"].source == "x = 1\nz = 3\ny = 2\n"


def test_deleted_and_binary_files_excluded(git_repo):
    base = git_repo.commit({"gone.py": "a\n", "img.png": b"\x89PNG\x00\x01"})
    head = git_repo.commit({"gone.py": None, "img.png": b"\x89PNG\x00\x02"})
    assert changed_files(git_repo.path, DiffRefs(base, head)) == []


def test_rename_reports_new_path(git_repo):
    base = git_repo.commit({"old.py": "a\nb\nc\nd\n"})
    git_repo.git("mv", "old.py", "new.py")
    head = git_repo.commit({"new.py": "a\nb\nc\nd\ne\n"})
    [f] = changed_files(git_repo.path, DiffRefs(base, head))
    assert (f.path, f.old_path, f.added) == ("new.py", "old.py", {5: "e"})


def test_read_at_decodes_gb18030(git_repo):
    sha = git_repo.commit({"a.c": "// 获取用户信息\n".encode("gb18030")})
    assert "获取用户信息" in read_at(git_repo.path, sha, "a.c")


def test_crlf_lines_stripped(git_repo):
    base = git_repo.commit({"a.txt": "a\r\n"})
    head = git_repo.commit({"a.txt": "a\r\nb\r\n"})
    assert changed_files(git_repo.path, DiffRefs(base, head))[0].added == {2: "b"}


def test_decode_bom_and_latin1():
    assert decode(b"\xef\xbb\xbfhi") == "hi"
    assert decode(b"\xff\xfe\xff") != ""


def test_whole_files_tracked_and_merge_base(git_repo):
    base = git_repo.commit({"a.py": "x\ny\n"})
    git_repo.branch("feat")
    git_repo.commit({"b.py": "z\n"})
    git_repo.git("checkout", "-q", "main")
    assert merge_base(git_repo.path, "main", "feat") == base
    assert sorted(tracked_files(git_repo.path)) == ["a.py"]
    [f] = whole_files(git_repo.path, ["a.py"])
    assert f.added == {1: "x", 2: "y"} and f.old_path is None


def test_path_with_space(git_repo):
    base = git_repo.commit({"x.py": "a\n"})
    head = git_repo.commit({"my file.py": "p\nq\n"})
    [f] = changed_files(git_repo.path, DiffRefs(base, head))
    assert f.path == "my file.py" and f.added == {1: "p", 2: "q"}


def test_path_with_double_quote(git_repo):
    base = git_repo.commit({"x.py": "a\n"})
    head = git_repo.commit({'we"ird.py': "p\n"})
    [f] = changed_files(git_repo.path, DiffRefs(base, head))
    assert f.path == 'we"ird.py' and f.added == {1: "p"}


def _submodule(git_repo, name="dep"):
    """An embedded repo committed as a gitlink (mode 160000), as `git submodule add` does."""
    import subprocess

    sub = git_repo.path / name
    sub.mkdir()
    for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@e"],
                 ["config", "user.name", "T"], ["config", "commit.gpgsign", "false"]):
        subprocess.run(["git", *args], cwd=sub, check=True, capture_output=True)
    (sub / "lib.py").write_text("y = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=sub, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "s"], cwd=sub, check=True, capture_output=True)
    return sub


def test_added_and_bumped_submodule_skipped(git_repo):
    base = git_repo.commit({"a.py": "x\n"})
    sub = _submodule(git_repo)
    added = git_repo.commit({"a.py": "x\ny\n"})
    assert [f.path for f in changed_files(git_repo.path, DiffRefs(base, added))] == ["a.py"]
    (sub / "lib.py").write_text("y = 2\n")
    import subprocess
    subprocess.run(["git", "commit", "-qam", "s2"], cwd=sub, check=True, capture_output=True)
    bumped = git_repo.commit({})
    assert git_repo.git("diff", "--name-only", added, bumped) == "dep"
    assert changed_files(git_repo.path, DiffRefs(added, bumped)) == []


def test_tracked_and_whole_files_skip_submodules(git_repo):
    git_repo.commit({"a.py": "x\n"})
    _submodule(git_repo)
    git_repo.commit({})
    assert tracked_files(git_repo.path) == ["a.py"]
    assert [f.path for f in whole_files(git_repo.path, ["a.py", "dep"])] == ["a.py"]
