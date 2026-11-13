# Air-gapped MR/PR Review Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CI-job agent that scans GitLab MRs and Azure DevOps PRs. It checks for hardcoded secrets (blocking), non-English comments and strings (advisory), and security issues judged by an on-prem LLM (advisory). It posts inline comments and also has an on-demand full-repo scan mode.

**Architecture:**
- **One Python package, one CLI** (`pr-agent review` / `pr-agent scan`), shipped as a self-contained container image.
- **The diff comes from local git** in the CI checkout. The platform APIs are used only to read and write comment threads, behind a small `Platform` protocol, so GitLab and Azure DevOps are interchangeable.
- **Checks are independent functions.** Each returns a `CheckResult`. Secrets use a vendored gitleaks binary and never touch the model.

**Tech Stack:** Python 3.12, httpx, pydantic v2, PyYAML, Pygments, lingua-language-detector, pathspec, Jinja2, pytest, gitleaks 8.21.2 (vendored binary), Docker.

**Spec:** `docs/superpowers/specs/2026-11-13-airgapped-pr-agent-design.md`

## Global Constraints

- **Python and packaging**
  - Python 3.12.
  - Package `airgap_pr_agent` under `src/`.
  - Console script `pr-agent`.
- **Network:** no network calls except to `LLM_BASE_URL` and the platform API. Nothing is downloaded at runtime: no rules, no models, no update checks, no telemetry.
- **Secrets**
  - Secret detection and blocking are deterministic. The model never sees, judges or dismisses a secret finding.
  - Secrets never appear unmasked in comments, logs, reports or model prompts.
  - Mask format: the first 4 characters + `****`. For secrets shorter than 8 characters, just `****`.
- **What blocks:** only secrets block. Security and non-English findings are advisory and never affect the exit code.
- **Exit codes:** `0` = no blocking findings; `1` = secrets found; `3` = internal error, including a gitleaks failure or a config error. The agent fails closed.
- **Model unreachable or not configured:** the security check is skipped, the summary says so, and the exit code is unaffected.
- **Platform targets**
  - GitLab: Free-tier features only, REST API v4, GitLab ≥ 15.0.
  - Azure DevOps Server: 2020 or later, `api-version=6.0`.
- **Environment variables**
  - LLM: `LLM_BASE_URL` (includes `/v1`), `LLM_API_KEY`, `LLM_MODEL`.
  - GitLab token: `PR_AGENT_GITLAB_TOKEN`. ADO token: `SYSTEM_ACCESSTOKEN`.
  - Gitleaks binary path: `GITLEAKS_BIN` (default `gitleaks`).
- **LLM defaults:** `prompt_token_budget: 8000`, `concurrency: 2`, `timeout_seconds: 120`, `retries: 2`, `max_requests_per_mr: 30`, `max_requests_full_scan: 300`.
- **Check defaults:** security `min_severity: medium`; non-English `min_words: 4`.
- **Config:** optional repo file `.pr-agent.yml`, deep-merged over the built-in `defaults.yml`.
- **Comment threads**
  - The agent touches only threads whose first note carries its marker (`<!-- pr-agent:fp=… -->` or `<!-- pr-agent:summary -->`). Human threads are never modified.
  - Exactly one summary comment per MR, edited in place.

## Review Focus

1. **A new push lands while the job runs.** The MR's latest diff head ≠ the head we scanned. Expected: no inline comments are posted (their positions would be wrong), the summary is still updated, and the exit code still reflects secrets. *Tests: Task 4 `test_head_moved_skips_inline`, Task 5 `test_can_post_inline_false_when_head_moved`.*
2. **gitleaks is missing, crashes, or the config file is invalid.** Expected: exit 3 (the job fails). It must never exit 0 and let a secret through. *Tests: Task 3 `test_gitleaks_failure_raises`, Task 4 `test_cli_exit_3_when_gitleaks_missing`.*
3. **A secret sits in a hunk the security check sends to the model.** Expected: the prompt contains only the masked form. *Test: Task 8 `test_prompt_never_contains_raw_secret`.*
4. **Source files not in UTF-8,** such as GBK/GB18030-encoded files with Chinese comments, which are likely at this company. Expected: decoded correctly and flagged. They must not turn into `�` and slip through. *Tests: Task 2 `test_read_at_decodes_gb18030`, Task 6 `test_gb18030_file_flagged_end_to_end`.*
5. **A huge MR** (hundreds of files or one giant file). Expected: model requests stop at the cap, the job finishes, and the summary names the files the model didn't review. *Test: Task 8 `test_request_cap_marks_rest_unreviewed`.*

---

## File Structure

```
pyproject.toml
src/airgap_pr_agent/
  __init__.py
  defaults.yml          # org-wide default config, baked into the image
  models.py             # Check, Severity, Finding, CheckResult
  config.py             # Config model + load_config()
  paths.py              # PathFilter (gitwildmatch globs)
  gitops.py             # DiffRefs, ChangedFile, changed_files(), read_at(), whole_files(), commits
  markers.py            # hidden HTML markers for bot comments
  summary.py            # render_inline(), render_summary()
  review.py             # MR-mode orchestration: run_checks(), reconcile(), run_review()
  fullscan.py           # run_full_scan()
  report.py             # JSON / HTML / SARIF writers
  llm.py                # OpenAI-compatible client
  cli.py                # argparse entry point
  checks/__init__.py
  checks/secrets.py     # gitleaks runner, masking, Redactor, secret_findings()
  checks/language.py    # non-English comments/strings
  checks/security.py    # LLM security review
  platforms/__init__.py
  platforms/base.py     # Thread, Platform protocol, LogOnlyPlatform
  platforms/gitlab.py
  platforms/azure.py
  templates/report.html.j2
templates/gitlab/pr-agent.gitlab-ci.yml
templates/azure/pr-agent.yml
Dockerfile
requirements.lock, requirements-dev.lock
scripts/fetch-gitleaks.sh, scripts/build-bundle.sh
vendor/gitleaks-8.21.2.sha256
docs/rollout.md
README.md
tests/...               # one test file per module, conftest.py with git_repo fixture
```

---

### Task 1: Project scaffold, core models, config, path filtering

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `src/airgap_pr_agent/__init__.py`, `src/airgap_pr_agent/models.py`, `src/airgap_pr_agent/config.py`, `src/airgap_pr_agent/defaults.yml`, `src/airgap_pr_agent/paths.py`
- Test: `tests/test_config.py`, `tests/test_paths.py`

**Interfaces:**
- **Produces, in `models.py`:**
  - `class Check(str, Enum)`: `SECRETS="secrets"`, `NON_ENGLISH="non_english"`, `SECURITY="security"`.
  - `class Severity(str, Enum)`: `LOW="low"`, `MEDIUM="medium"`, `HIGH="high"`, with property `rank -> int` (0/1/2).
  - `@dataclass(frozen=True) class Finding`, with fields `check: Check`, `path: str`, `line: int | None`, `severity: Severity`, `title: str`, `message: str`, `fingerprint: str`, `commit: str | None = None`, `rule: str = ""`, `suggestion: str | None = None`. `line=None` means a summary-level finding.
  - `@dataclass class CheckResult`, with fields `check: Check`, `findings: list[Finding]`, `status: Literal["ok","skipped","partial"] = "ok"`, `note: str = ""`, `unreviewed: list[str] = field(default_factory=list)`.
  - `def fingerprint(*parts: str) -> str`: the first 16 hex chars of sha256 over `"|".join(parts)`.
- **Produces, in `config.py`:**
  - The pydantic `Config` model and its sections:
    - `checks: ChecksConfig(secrets, non_english, security: bool)`
    - `paths: PathsConfig(include: list[str], exclude: list[str])`
    - `security: SecurityConfig(min_severity: Severity, context_lines: int)`
    - `non_english: NonEnglishConfig(min_words: int, min_confidence: float, exclude: list[str])`
    - `secrets: SecretsConfig(allowlist: list[AllowEntry])`
    - `llm: LLMConfig(prompt_token_budget, concurrency, timeout_seconds, retries, max_requests_per_mr, max_requests_full_scan: int; json_mode: bool)`
    - `full_scan: FullScanConfig(fail_on_secrets: bool, sarif: bool)`
  - `AllowEntry(fingerprint: str | None = None, path: str | None = None)`. At least one of the two is required.
  - `class ConfigError(Exception)`.
  - `def load_config(repo: Path) -> Config`.
- **Produces, in `paths.py`:**
  - `class PathFilter`: `__init__(include: list[str], exclude: list[str])`, `allows(path: str) -> bool`, and `classmethod from_globs(include, exclude, extra_exclude: list[str] = []) -> PathFilter`.

- [ ] **Step 1: Write `pyproject.toml`.** Use a setuptools src layout. Runtime deps: `httpx`, `pydantic>=2`, `pyyaml`, `pygments`, `lingua-language-detector`, `pathspec`, `jinja2`. The dev extra is `pytest`, `pip-tools`. Add the console script `pr-agent = "airgap_pr_agent.cli:main"`. Include `defaults.yml` and `templates/*.j2` as package data. Set pytest `testpaths = ["tests"]`.

- [ ] **Step 2: Write `defaults.yml`** with these exact values:

```yaml
checks: {secrets: true, non_english: true, security: true}
paths:
  include: ["**"]
  exclude: ["**/vendor/**", "**/node_modules/**", "**/third_party/**", "**/dist/**", "**/build/**",
            "**/*.min.js", "**/*.min.css", "**/*_pb2.py", "**/*.pb.go", "**/*.generated.*",
            "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/poetry.lock", "**/Pipfile.lock",
            "**/Cargo.lock", "**/go.sum", "**/composer.lock", "**/Gemfile.lock", "**/*.lock"]
security: {min_severity: medium, context_lines: 20}
non_english:
  min_words: 4
  min_confidence: 0.7
  exclude: ["**/locale/**", "**/locales/**", "**/i18n/**", "**/*.po", "**/*.pot", "**/*.??.resx", "**/*.??-??.resx",
            "**/testdata/**", "**/fixtures/**", "**/__fixtures__/**"]
secrets: {allowlist: []}
llm: {prompt_token_budget: 8000, concurrency: 2, timeout_seconds: 120, retries: 2,
      max_requests_per_mr: 30, max_requests_full_scan: 300, json_mode: false}
full_scan: {fail_on_secrets: true, sarif: false}
```

`paths.exclude` applies to the non-English and security checks only. Secrets scanning ignores path excludes and honours only `secrets.allowlist`; a leaked key in `vendor/` is still a leak.

- [ ] **Step 3: Write the failing tests.**

```python
# tests/test_config.py
def test_defaults_load_without_repo_file(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.checks.secrets and cfg.checks.non_english and cfg.checks.security
    assert cfg.security.min_severity == Severity.MEDIUM
    assert cfg.non_english.min_words == 4
    l = cfg.llm
    assert (l.prompt_token_budget, l.concurrency, l.timeout_seconds, l.retries,
            l.max_requests_per_mr, l.max_requests_full_scan) == (8000, 2, 120, 2, 30, 300)
    assert cfg.full_scan.fail_on_secrets is True and cfg.full_scan.sarif is False

def test_repo_file_deep_merges(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("security:\n  min_severity: high\nllm:\n  concurrency: 4\n")
    cfg = load_config(tmp_path)
    assert cfg.security.min_severity == Severity.HIGH
    assert cfg.security.context_lines == 20
    assert cfg.llm.concurrency == 4 and cfg.llm.max_requests_per_mr == 30

def test_invalid_value_raises_config_error(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("security:\n  min_severity: urgent\n")
    with pytest.raises(ConfigError, match="min_severity"):
        load_config(tmp_path)

def test_allowlist_entry_requires_fingerprint_or_path(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("secrets:\n  allowlist:\n    - {fingerprint: abcd}\n    - {path: 'tests/**'}\n")
    assert [e.path for e in load_config(tmp_path).secrets.allowlist] == [None, "tests/**"]
    (tmp_path / ".pr-agent.yml").write_text("secrets:\n  allowlist:\n    - {}\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)

# tests/test_paths.py
@pytest.mark.parametrize("p", ["package-lock.json", "web/yarn.lock", "vendor/x/a.go", "node_modules/a/b.js",
                               "static/app.min.js", "api/user_pb2.py", "dist/bundle.js"])
def test_default_excludes(tmp_path, p):
    cfg = load_config(tmp_path)
    assert PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude).allows(p) is False

def test_source_allowed_and_user_globs():
    f = PathFilter.from_globs(["src/**"], ["src/gen/**"])
    assert f.allows("src/app.py") and not f.allows("src/gen/x.py") and not f.allows("docs/a.py")

def test_extra_exclude(tmp_path):
    cfg = load_config(tmp_path)
    f = PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude, cfg.non_english.exclude)
    assert not f.allows("app/locales/zh.json") and not f.allows("Res/Strings.zh-CN.resx")
```

- [ ] **Step 4: Run `pytest tests/test_config.py tests/test_paths.py -v`.** Expected: FAIL (an ImportError).
- [ ] **Step 5: Implement `models.py`, `config.py` and `paths.py`.**
  - `load_config` reads `defaults.yml` with `importlib.resources`, recursively merges the dicts from the repo file over it (lists are replaced, not concatenated), then validates.
  - It wraps a pydantic `ValidationError` or a YAML error in a `ConfigError` whose message includes the field path.
  - `PathFilter` uses `pathspec.PathSpec.from_lines("gitwildmatch", …)`.
- [ ] **Step 6: Run the same tests.** Expected: PASS.
- [ ] **Step 7: Commit:** `git commit -m "feat: scaffold package with models, config and path filter"`

---

### Task 2: Git diff and file reading

**Files:**
- Create: `src/airgap_pr_agent/gitops.py`, `tests/conftest.py`
- Test: `tests/test_gitops.py`

**Interfaces:**
- **Produces:**
  - `@dataclass(frozen=True) class DiffRefs`, with fields `base: str`, `head: str`.
  - `@dataclass class ChangedFile`, with fields `path: str`, `old_path: str | None`, `added: dict[int, str]` (head line number → line text), `source: str` (the full head file text).
  - `def changed_files(repo: Path, refs: DiffRefs) -> list[ChangedFile]`. It covers added, modified and renamed files only; deleted and binary files are left out.
  - `def read_at(repo: Path, rev: str, path: str) -> str`.
  - `def decode(data: bytes) -> str`: tries utf-8 (BOM-aware), then gb18030, then latin-1.
  - `def whole_files(repo: Path, paths: list[str]) -> list[ChangedFile]`. It reads from the working tree, and every line counts as "added".
  - `def tracked_files(repo: Path) -> list[str]`.
  - `def merge_base(repo: Path, a: str, b: str) -> str`.
  - `class GitError(Exception)`.
- **Produces, in `tests/conftest.py`:**
  - The `git_repo` fixture returns a `GitRepo` with `path: Path`, `git(*args) -> str`, `commit(files: dict[str, str | bytes | None], msg: str = "c") -> str` (where `None` deletes the file, and it returns the sha) and `branch(name)`.
  - The `requires_gitleaks` marker skips the test when `shutil.which(os.environ.get("GITLEAKS_BIN", "gitleaks"))` is None. When `PR_AGENT_REQUIRE_GITLEAKS=1`, it fails instead.

- [ ] **Step 1: Write the failing tests.**

```python
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
```

- [ ] **Step 2: Run `pytest tests/test_gitops.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement `gitops.py`.**
  - Run `git -c core.quotepath=off diff --no-color --unified=0 --find-renames --diff-filter=AMR <base> <head>` and parse the `diff --git` / `rename from` / `+++ b/` headers and the `@@ -a,b +c,d @@` hunks to get the added line numbers.
  - Detect binaries with `git diff --numstat` (a `-` in the stats).
  - Take line texts from `read_at(head)`, split with `splitlines()`. Don't take them from the diff bytes, so the decoding stays consistent.
  - All git calls go through one `_git(repo, *args) -> bytes` helper, which raises `GitError` with stderr on a non-zero exit.
- [ ] **Step 4: Run the tests.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: git diff parsing with robust decoding"`

---

### Task 3: Secrets check (gitleaks, masking, allowlist, redactor)

**Files:**
- Create: `src/airgap_pr_agent/checks/__init__.py`, `src/airgap_pr_agent/checks/secrets.py`
- Test: `tests/checks/test_secrets.py`

**Interfaces:**
- **Consumes:** `Finding`, `CheckResult`, `Check`, `Severity`, `fingerprint` (Task 1); `AllowEntry`, `PathFilter` (Task 1); `ChangedFile`, `DiffRefs` (Task 2).
- **Produces:**
  - `class SecretScanError(Exception)`.
  - `def mask(secret: str) -> str`.
  - `class Redactor`: `__init__(secrets: Iterable[str])`, `redact(text: str) -> str`.
  - `def run_gitleaks(repo: Path, mode: Literal["range", "dir", "history"], refs: DiffRefs | None = None, bin: str = "gitleaks") -> list[dict]`.
  - `def secret_findings(leaks: list[dict], changed: list[ChangedFile] | None, allowlist: list[AllowEntry]) -> tuple[CheckResult, Redactor]`. `changed=None` means full-scan mode: findings keep gitleaks' `StartLine`.
- **Fingerprint:** `fingerprint("secrets", RuleID, File, sha256(Secret).hexdigest())`. It's stable across line moves and commits.
- **Finding fields:** `severity=HIGH`, `rule=RuleID`, `title=f"Hardcoded secret ({Description})"`, and a `message` that contains `mask(Secret)` and the fingerprint (so developers can copy it into the allowlist). The raw value is never in any field.

- [ ] **Step 1: Write the failing tests.**

```python
RAW = "Hunter2!prodSecret"
LEAK = {"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "app.py",
        "StartLine": 3, "Secret": RAW, "Match": f'password = "{RAW}"', "Commit": "abc123"}
CF = ChangedFile("app.py", None, {3: f'password = "{RAW}"'}, f'a\nb\npassword = "{RAW}"\n')

def test_mask():
    assert mask(RAW) == "Hunt****" and mask("short") == "****"

def test_inline_when_still_on_changed_line():
    res, _ = secret_findings([LEAK], [CF], [])
    [f] = res.findings
    assert (f.line, f.severity, f.check) == (3, Severity.HIGH, Check.SECRETS)
    assert RAW not in repr(f) and "Hunt****" in f.message and f.fingerprint in f.message

def test_summary_level_when_removed_in_later_commit():
    res, _ = secret_findings([LEAK], [ChangedFile("app.py", None, {1: "x"}, "x\n")], [])
    assert res.findings[0].line is None and res.findings[0].commit == "abc123"

def test_same_secret_in_two_commits_deduped_preferring_inline():
    older = {**LEAK, "Commit": "old111", "StartLine": 9}
    res, _ = secret_findings([older, LEAK], [CF], [])
    assert [(f.line, f.commit) for f in res.findings] == [(3, "abc123")]

def test_allowlist_by_fingerprint_and_path():
    res, _ = secret_findings([LEAK], [CF], [])
    fp = res.findings[0].fingerprint
    assert secret_findings([LEAK], [CF], [AllowEntry(fingerprint=fp)])[0].findings == []
    assert secret_findings([LEAK], [CF], [AllowEntry(path="*.py")])[0].findings == []

def test_full_scan_mode_keeps_start_line():
    assert secret_findings([LEAK], None, [])[0].findings[0].line == 3

def test_redactor():
    _, red = secret_findings([LEAK], [CF], [])
    assert red.redact(f"x={RAW}; y={RAW}") == "x=Hunt****; y=Hunt****"

def test_gitleaks_failure_raises(tmp_path):
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "dir", bin="/nonexistent/gitleaks")
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "dir", bin="false")

@pytest.mark.requires_gitleaks
def test_real_gitleaks_range_catches_added_then_removed(git_repo):
    base = git_repo.commit({"a.py": "x = 1\n"})
    git_repo.commit({"a.py": 'aws_access_key_id = "AKIA2E0A8F3B244C9986"\n'})
    head = git_repo.commit({"a.py": "x = 1\n"})
    leaks = run_gitleaks(git_repo.path, "range", DiffRefs(base, head), bin=os.environ.get("GITLEAKS_BIN", "gitleaks"))
    assert any("AKIA2E0A8F3B244C9986" == l["Secret"] for l in leaks)
```

- [ ] **Step 2: Run `pytest tests/checks/test_secrets.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement `secrets.py`.**
  - **Commands** (gitleaks 8.21.2, always with `--no-banner --exit-code 0 --report-format json --report-path <tmpfile>`):
    - range: `gitleaks git --log-opts "<base>..<head>" <repo>`
    - dir: `gitleaks dir <repo>`
    - history: `gitleaks git <repo>`
  - **Report file:** write it inside a `tempfile.TemporaryDirectory()` and delete it straight after reading.
  - **Errors:** a non-zero exit, a missing binary or unparseable JSON raises `SecretScanError`, with stderr included. stderr must never contain the report.
  - **Inline vs summary:** a finding is inline when `File` is a changed path, `StartLine` is in `added`, and `Secret.splitlines()[0]` occurs in that line's text. Otherwise `line=None`.
  - **`Redactor`:** replaces the longest secrets first.
- [ ] **Step 4: Run the tests.** Expected: PASS. The `requires_gitleaks` test passes if you have gitleaks installed locally (`brew install gitleaks`) and is skipped otherwise.
- [ ] **Step 5: Commit:** `git commit -m "feat: deterministic secrets check via gitleaks"`

---

### Task 4: Review orchestration, comment reconciliation, summary, CLI `review`

**Files:**
- Create: `src/airgap_pr_agent/markers.py`, `summary.py`, `review.py`, `cli.py`, `__main__.py` (calls `sys.exit(main())`, so `python -m airgap_pr_agent` works for the wheel-bundle fallback), `platforms/__init__.py`, `platforms/base.py`
- Test: `tests/test_review.py`, `tests/test_cli.py`, `tests/fakes.py`

**Interfaces:**
- **Consumes:** Tasks 1–3.
- **Produces, in `markers.py`:** `SUMMARY_MARKER = "<!-- pr-agent:summary -->"`, `def fp_marker(fp: str) -> str` (returns `<!-- pr-agent:fp=<fp> -->`), and `def parse_fp(body: str) -> str | None`.
- **Produces, in `platforms/base.py`:**
  - `@dataclass class Thread`, with fields `id: str`, `body: str` (the first note), `resolved: bool`, `note_id: str | None`.
  - `class Platform(Protocol)`:
    - `diff_refs() -> DiffRefs`
    - `can_post_inline() -> bool`
    - `list_threads() -> list[Thread]`
    - `post_inline(path: str, line: int, body: str) -> None`
    - `set_resolved(thread_id: str, resolved: bool) -> None`
    - `upsert_summary(body: str, existing: Thread | None) -> None`
  - `class LogOnlyPlatform(refs: DiffRefs)` prints inline comments and the summary to stdout and has no threads.
  - `class PlatformError(Exception)`, which adapters raise on any non-2xx API response.
- **Produces, in `summary.py`:** `def render_inline(f: Finding) -> str` and `def render_summary(results: list[CheckResult], blocked: bool) -> str`.
- **Produces, in `review.py`:**
  - `def run_checks(repo: Path, changed: list[ChangedFile], refs: DiffRefs | None, cfg: Config, llm, gitleaks_bin: str) -> list[CheckResult]`. In this task it runs secrets only; Tasks 6 and 8 add their checks here.
  - `def reconcile(findings: list[Finding], threads: list[Thread], platform: Platform) -> None`.
  - `def run_review(repo: Path, platform: Platform, cfg: Config, llm, gitleaks_bin: str) -> int`.
- **Produces, in `cli.py`:** `def main(argv: list[str] | None = None) -> int`, with the subcommand `review [--repo .] [--platform auto|gitlab|azure|local] [--base SHA] [--head SHA]`.
- **Exact copy:**
  - The block line in the summary: `**Merge blocked:** {n} hardcoded secret(s) found. Remove them and **rotate each secret**: deleting it from the code does not remove it from git history.`
  - The skipped-check line: `⚠️ {Check title} check skipped: {note}`.
  - When nothing is found: `✅ No issues found.`

- [ ] **Step 1: Write `tests/fakes.py`** with a `FakePlatform(refs, threads=[], inline_ok=True, fail_posts=False)` that records `posted`, `resolved`, `summaries` lists.
- [ ] **Step 2: Write the failing tests.**

```python
def test_secret_on_changed_line_posts_inline_and_blocks(git_repo, tmp_cfg):
    base = git_repo.commit({"a.py": "x = 1\n"})
    head = git_repo.commit({"a.py": 'x = 1\ntoken = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"\n'})
    p = FakePlatform(DiffRefs(base, head))
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 1
    [(path, line, body)] = p.posted
    assert (path, line) == ("a.py", 2) and "ghp_1234567890" not in body and "<!-- pr-agent:fp=" in body
    assert "Merge blocked" in p.summaries[-1] and "rotate each secret" in p.summaries[-1]

def test_clean_mr_exit_0_and_summary_ok(...):  # summary contains "✅ No issues found."
def test_existing_thread_not_reposted(...):     # thread body has fp_marker(fp) → posted == []
def test_stale_bot_thread_resolved_human_untouched(...):
    # threads: bot thread fp "dead" (open), human thread "LGTM" → resolved == [("t1", True)] only
def test_resolved_bot_thread_reopened_when_finding_returns(...):  # resolved == [(id, False)]
def test_head_moved_skips_inline(...):          # inline_ok=False → posted == [], summary updated, exit 1
def test_post_failure_still_blocks_and_logs(capsys, ...):  # fail_posts=True → exit 1, "a.py:2" in stdout
def test_secrets_disabled_by_config(...):       # checks.secrets False → exit 0

# tests/test_cli.py
def test_cli_local_review_blocks_on_secret(git_repo, monkeypatch): ...  # main(["review","--platform","local","--repo",p,"--base",base]) == 1
def test_cli_exit_3_when_gitleaks_missing(git_repo, monkeypatch):
    monkeypatch.setenv("GITLEAKS_BIN", "/nonexistent/gitleaks")
    assert main(["review", "--platform", "local", "--repo", str(git_repo.path), "--base", base]) == 3
def test_cli_exit_3_on_bad_config(...):          # invalid .pr-agent.yml → 3, message names the field on stderr
def test_python_dash_m_runs(): ...               # subprocess [sys.executable, "-m", "airgap_pr_agent", "--help"] exits 0
```

  (`tmp_cfg` = `load_config(tmp_path)` and `GITLEAKS` = `os.environ.get("GITLEAKS_BIN","gitleaks")` go in conftest. Tests that run real gitleaks carry `requires_gitleaks`.)

- [ ] **Step 3: Run `pytest tests/test_review.py tests/test_cli.py -v`.** Expected: FAIL.
- [ ] **Step 4: Implement.**
  - **`run_review` order:**
    1. Get `refs`.
    2. Compute `changed_files`.
    3. Call `run_checks`.
    4. Compute `blocked = any secrets findings`.
    5. If `can_post_inline()`, call `reconcile`.
    6. Call `upsert_summary(render_summary(...), existing summary thread or None)`.
    7. Return `1 if blocked else 0`.
  - **Platform errors** (`httpx.HTTPError`, `PlatformError`) in steps 5–6 are caught. The agent prints every finding as `path:line: title` to stdout and still returns the blocked status.
  - **`reconcile`:**
    - Post each inline finding (`line is not None`) whose fp has no thread.
    - Unresolve a resolved bot thread whose fp is current.
    - Resolve an open bot thread whose fp isn't current.
    - Ignore threads without markers and the summary thread.
  - **`render_summary` contains:**
    - a per-check count table by severity;
    - the block line;
    - summary-level secret findings with their short commit SHA and masked value;
    - a skipped/partial note per check;
    - `Files not reviewed by the model:` with `unreviewed`.
  - **`cli.main`:**
    - It loads config from `--repo` and builds an LLM client (`None` until Task 7).
    - It picks the platform: `local` → `LogOnlyPlatform`, which needs `--base`; `--head` defaults to `HEAD`.
    - Any `SecretScanError`, `ConfigError`, `GitError` or unexpected exception prints `pr-agent: error: <msg>` to stderr and returns 3.
- [ ] **Step 5: Run the tests.** Expected: PASS.
- [ ] **Step 6: Commit:** `git commit -m "feat: MR review orchestration, comment reconciliation and CLI"`

---

### Task 5: GitLab adapter and CI template

**Files:**
- Create: `src/airgap_pr_agent/platforms/gitlab.py`, `templates/gitlab/pr-agent.gitlab-ci.yml`
- Modify: `src/airgap_pr_agent/cli.py` (platform auto-detection)
- Test: `tests/platforms/test_gitlab.py`, `tests/test_templates.py`

**Interfaces:**
- **Consumes:** `Platform`, `Thread`, `LogOnlyPlatform` (Task 4); `DiffRefs` (Task 2).
- **Produces:**
  - `def refs_from_env(env: Mapping[str, str]) -> DiffRefs`. It uses `base = CI_MERGE_REQUEST_DIFF_BASE_SHA` and `head = CI_MERGE_REQUEST_SOURCE_BRANCH_SHA or CI_COMMIT_SHA`; the source-branch SHA is set in merged-results pipelines.
  - `class GitLabPlatform(api_url: str, project_id: str, mr_iid: str, token: str, refs: DiffRefs, transport: httpx.BaseTransport | None = None)`, which implements `Platform`.
  - `classmethod from_env(env) -> GitLabPlatform | None`. It returns `None` if `PR_AGENT_GITLAB_TOKEN` is unset. It uses `CI_API_V4_URL`, `CI_PROJECT_ID` and `CI_MERGE_REQUEST_IID`.
- **API calls** (header `PRIVATE-TOKEN`):

| Operation | Call |
|---|---|
| Versions | `GET /projects/:id/merge_requests/:iid/versions` (`[0]` = latest; `base_commit_sha`, `start_commit_sha`, `head_commit_sha`) |
| List | `GET …/discussions?per_page=100`, following `X-Next-Page` |
| Post inline | `POST …/discussions` with `body`, `position[position_type]=text`, `position[base_sha]`, `position[start_sha]`, `position[head_sha]`, `position[new_path]`, `position[new_line]` |
| Resolve | `PUT …/discussions/:did?resolved=true\|false` |
| Summary | `POST …/notes`, or `PUT …/notes/:note_id` |

- [ ] **Step 1: Write the failing tests** using `httpx.MockTransport` with handlers that record requests:
  - `test_refs_prefers_source_branch_sha`
  - `test_list_threads_paginates_and_maps_first_note`: two pages, where `resolved` comes from `notes[0].resolved`
  - `test_post_inline_uses_versions_shas`: asserts the JSON body `position` equals the versions shas plus `new_path`/`new_line`
  - `test_can_post_inline_false_when_head_moved`: versions `head_commit_sha` ≠ `refs.head` → `False`
  - `test_set_resolved_puts_flag`
  - `test_summary_post_then_put`: `existing=None` → POST notes; `existing=Thread(note_id="9")` → PUT notes/9
  - `test_from_env_none_without_token`
  - `test_cli_auto_detects_gitlab_and_falls_back_to_log_only`: `GITLAB_CI=true` with no token → `LogOnlyPlatform` with the env refs, and a warning on stderr
  - In `tests/test_templates.py`, `test_gitlab_template`: load the YAML; job `pr-agent-review` has `rules == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}]`, `variables.GIT_DEPTH == "0"`, `script == ["pr-agent review"]`, `image.entrypoint == [""]`
- [ ] **Step 2: Run `pytest tests/platforms/test_gitlab.py tests/test_templates.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement the adapter and the template.**
  - **Adapter:** one `httpx.Client` with `timeout=30`. A non-2xx response raises `PlatformError` (from `platforms/base.py`).
  - **CLI auto-detection:** `GITLAB_CI == "true"` → GitLab; `TF_BUILD == "True"` → Azure (Task 10); otherwise error unless `--platform local`.
  - **Template:** a hidden `.pr-agent` job with `image: {name: $PR_AGENT_IMAGE, entrypoint: [""]}` and `variables: {GIT_DEPTH: "0", PR_AGENT_IMAGE: "registry.internal/devtools/pr-agent:1"}`. The registry path is a placeholder that teams override. Add `pr-agent-review` with `extends: .pr-agent` and `stage: test`.
- [ ] **Step 4: Run the tests.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: GitLab adapter and CI template"`

---

### Task 6: Non-English comments and strings check

**Files:**
- Create: `src/airgap_pr_agent/checks/language.py`
- Modify: `src/airgap_pr_agent/review.py` (`run_checks` adds this check when `cfg.checks.non_english`)
- Test: `tests/checks/test_language.py`

**Interfaces:**
- **Consumes:** `ChangedFile` (Task 2), `NonEnglishConfig` and `PathFilter` (Task 1).
- **Produces:**
  - `@dataclass class TextSpan`, with fields `start: int`, `end: int`, `kind: Literal["comment", "string", "line"]`, `text: str`.
  - `def extract_spans(path: str, source: str) -> list[TextSpan]`. When Pygments has no lexer for the file, it returns one `kind="line"` span per line.
  - `def classify(text: str, min_words: int, min_confidence: float, latin_check: bool = True) -> str | None`. It returns a reason string, or `None`.
  - `def non_english_findings(files: list[ChangedFile], cfg: NonEnglishConfig, path_filter: PathFilter) -> CheckResult`.
- **Rules:**
  - **Cleaning, before classifying:** strip URLs (`https?://\S+`), file paths, `%s`/`%d`-style placeholders, `{…}` and `${…}` placeholders, and escape sequences.
  - **Non-Latin rule:** any char where `ch.isalpha()` and `not unicodedata.name(ch, "").startswith("LATIN")` → reason `f"non-Latin script ({script})"`. `script` is the first word of the char's Unicode name, title-cased, e.g. `Cjk`. Map `CJK` → `Chinese/Japanese`. This applies at any length.
  - **Latin rule (only when `latin_check`):**
    - Applies only when the text has ≥ `min_words` words (`re.findall(r"[^\W\d_]+")`).
    - Uses one cached `LanguageDetectorBuilder.from_all_languages().with_low_accuracy_mode().build()`.
    - Flags when the top `compute_language_confidence_values` entry isn't `Language.ENGLISH` and its value is ≥ `min_confidence`. Reason: `f"{language.name.title()} text"`.
  - **Fallback `line` spans** run with `latin_check=False`, because raw code lines confuse the language detector.
  - **Which line gets the comment:** a span is checked if any line in `start..end` is in `file.added`. The finding goes on the first such line, with one finding per span.
  - **Finding fields:** `severity=LOW`, `title="Non-English text in comment"` / `"Non-English text in string"`, and a `message` that quotes up to 80 chars of the text plus the reason. `fingerprint("non_english", path, kind, normalized_text)`.

- [ ] **Step 1: Write the failing tests.**

```python
def test_extract_python_comment_and_string():
    spans = extract_spans("a.py", '# 获取用户\nx = "hello"\n')
    assert [(s.start, s.kind) for s in spans] == [(1, "comment"), (2, "string")]

@pytest.mark.parametrize("text,expect", [
    ("获取用户信息", "non-Latin"), ("Получить пользователя", "non-Latin"),
    ("Get the current user info", None), ("Obtener la información del usuario actual", "Spanish"),
    ("ok", None), ("café", None), ("see https://例子.com/x", None), ("%s {name} ${x}", None)])
def test_classify(text, expect):
    r = classify(text, 4, 0.7)
    assert (r is None) if expect is None else (expect in r)

def test_only_changed_lines(tmp_path):
    f = ChangedFile("a.py", None, {2: "# 新的"}, "# 旧的\n# 新的\n")
    [finding] = non_english_findings([f], CFG, FILTER).findings
    assert finding.line == 2 and finding.severity == Severity.LOW

def test_multiline_block_comment_reported_once(): ...  # /* 第一行\n 第二行 */ in .c with both lines added → 1 finding at line 1
def test_locale_file_excluded(): ...                     # path "app/locales/zh.json" → no findings
def test_unknown_extension_non_latin_only(): ...         # "notes.xyz": "数据" flagged; Spanish sentence not flagged
def test_gb18030_file_flagged_end_to_end(git_repo):
    base = git_repo.commit({"a.c": "int x;\n"})
    head = git_repo.commit({"a.c": "int x;\n// 获取用户信息\n".encode("gb18030")})
    res = non_english_findings(changed_files(git_repo.path, DiffRefs(base, head)), CFG, FILTER)
    assert [f.line for f in res.findings] == [2]
```

- [ ] **Step 2: Run `pytest tests/checks/test_language.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement `language.py`.**
  - **Lexing:** `pygments.lexers.get_lexer_for_filename(path, source)`, catching `ClassNotFound` and falling back.
  - **Token kinds:** `Token.Comment` subtypes and `Token.Literal.String.Doc` → comment; other `Token.Literal.String` subtypes → string. Merge consecutive tokens of the same kind into one span, tracking line numbers by counting `\n`.
  - **Wiring:** add the check to `run_checks` with `PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude, cfg.non_english.exclude)`.
- [ ] **Step 4: Run the tests and the full suite.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: non-English comment and string check"`

---

### Task 7: OpenAI-compatible LLM client

**Files:**
- Create: `src/airgap_pr_agent/llm.py`
- Modify: `src/airgap_pr_agent/cli.py` (build the client with `max_requests=cfg.llm.max_requests_per_mr`)
- Test: `tests/test_llm.py`

**Interfaces:**
- **Consumes:** `LLMConfig` (Task 1).
- **Produces:**
  - `class LLMUnavailable(Exception)` and `class RequestCapReached(Exception)`.
  - `class LLMClient(base_url: str, api_key: str, model: str, *, timeout: float, retries: int, max_requests: int, json_mode: bool = False, transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep)`:
    - `complete_json(system: str, user: str) -> dict`. It raises `LLMUnavailable`, `RequestCapReached`, or `ValueError` for an unparseable reply.
    - `requests_made: int`.
    - It's thread-safe.
  - `classmethod from_env(cfg: LLMConfig, env: Mapping[str, str], max_requests: int) -> LLMClient | None`. It returns `None` unless both `LLM_BASE_URL` and `LLM_API_KEY` are set. `LLM_MODEL` defaults to `"default"`.
  - `def extract_json(text: str) -> dict`. It strips code fences and parses the outermost `{…}`.

- [ ] **Step 1: Write the failing tests** with `httpx.MockTransport` and `sleep=lambda s: None`:
  - `test_request_shape`: `POST {base}/chat/completions`, `Authorization: Bearer k`, body `model`, `temperature == 0`, and `messages[0].role == "system"`
  - `test_json_mode_adds_response_format`: body `response_format == {"type": "json_object"}`
  - `test_extract_json_from_fenced_reply`: content ```` ```json\n{"findings": []}\n``` ```` → `{"findings": []}`
  - `test_retries_5xx_then_succeeds`: 500, then 200 → 2 calls
  - `test_timeouts_exhaust_to_unavailable`: the handler raises `httpx.ReadTimeout` → `LLMUnavailable` after `retries + 1 == 3` calls
  - `test_401_no_retry`: 1 call, then `LLMUnavailable`
  - `test_cap_reached_without_http`: `max_requests=2`; the third call raises `RequestCapReached`, and the transport is called twice
  - `test_from_env_none_when_unset`
  - `test_api_key_never_in_error_message`: on 401, `"k-secret"` not in `str(exc)`
- [ ] **Step 2: Run `pytest tests/test_llm.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement it.**
  - **Retries** on `httpx.TransportError` (including timeouts), 429 and 5xx, with backoff `sleep(2 ** attempt)`.
  - **Other 4xx** → `LLMUnavailable(f"model endpoint returned {status}")`.
  - **The request counter** increments under a `threading.Lock` before sending. If it's already at `max_requests`, raise `RequestCapReached`.
- [ ] **Step 4: Run the tests.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: OpenAI-compatible LLM client with retries and caps"`

---

### Task 8: Security check (LLM)

**Files:**
- Create: `src/airgap_pr_agent/checks/security.py`
- Modify: `src/airgap_pr_agent/review.py` (`run_checks` adds this check when `cfg.checks.security`, passing the secrets `Redactor`. If the secrets check is disabled, use `Redactor([])`.)
- Test: `tests/checks/test_security.py`

**Interfaces:**
- **Consumes:** `LLMClient`, `LLMUnavailable`, `RequestCapReached` (Task 7); `Redactor` (Task 3); `ChangedFile` (Task 2); `SecurityConfig`, `LLMConfig`, `PathFilter` (Task 1).
- **Produces:**
  - `@dataclass class Chunk`, with fields `path: str`, `start: int`, `end: int`, `changed: set[int]`, `text: str`.
  - `def build_chunks(files: list[ChangedFile], context_lines: int, token_budget: int) -> list[Chunk]`.
  - `def security_findings(files: list[ChangedFile], client: LLMClient | None, cfg: SecurityConfig, llm_cfg: LLMConfig, redactor: Redactor, path_filter: PathFilter) -> CheckResult`.
  - `SYSTEM_PROMPT: str`.
- **Chunk format:** each line is `f"{n:>6} {'+' if n in changed else ' '} {text}"`.
  - Each changed-line window is extended by `context_lines`, and overlapping windows are merged.
  - A chunk's text is capped at `(token_budget - 1500) * 4` chars, splitting on line boundaries.
  - `redactor.redact` is applied to the chunk text.
- **Model contract:** the prompt asks for `{"findings": [{"line": int, "severity": "high"|"medium"|"low", "category": str, "explanation": str, "suggestion": str}]}`, for the lines marked `+` only, and for real exploitable issues only.
  - Replies are validated with a pydantic model. Invalid items are dropped.
  - `path` always comes from the chunk, never from the model.
  - Lines not in `chunk.changed` and severities below `cfg.min_severity` are dropped.
- **Finding fields:** `title=f"Security: {category}"`, `message=explanation`, `suggestion`, and `fingerprint("security", path, category, normalized line text)`.
- **Statuses:**

| Situation | `status` | `note` |
|---|---|---|
| `client is None` | `skipped` | `"model not configured"` |
| First chunk raises `LLMUnavailable` | `skipped` | `"model unreachable"` |
| `LLMUnavailable` after some chunks succeeded | `partial` | `"model unreachable"` |
| `RequestCapReached` | `partial` | `"request cap reached"` |
| Unparseable reply | `partial` | that chunk's path goes in `unreviewed` |

  `unreviewed` is the sorted, unique list of paths of chunks that weren't completed. Chunks run in a `ThreadPoolExecutor(llm_cfg.concurrency)`. After `LLMUnavailable` or `RequestCapReached`, pending futures are cancelled.

- [ ] **Step 1: Write the failing tests** (the fake client is a `MockTransport`-backed `LLMClient` returning canned JSON):

```python
def test_chunks_number_and_mark_lines(): ...      # changed {5}; context 2 → lines 3..7 present, line 5 has "+"
def test_chunks_respect_budget(): ...             # 2000 changed lines, token_budget 2000 → every len(c.text) <= (2000 - 1500) * 4
def test_keeps_valid_finding_on_changed_line(): ...
def test_drops_off_diff_line_and_low_severity(): ...
def test_model_path_ignored(): ...                # reply says "path": "other.py" → finding.path == chunk path
def test_unparseable_reply_marks_file_unreviewed(): ...
def test_prompt_never_contains_raw_secret():
    raw = "Hunter2!prodSecret"
    f = ChangedFile("a.py", None, {1: f'pw = "{raw}"'}, f'pw = "{raw}"\n')
    sent = []
    res = security_findings([f], client_capturing(sent), SEC, LLM, Redactor([raw]), FILTER)
    assert sent and all(raw not in body for body in sent) and any("Hunt****" in b for b in sent)
def test_no_client_skipped(): ...                 # status "skipped", note "model not configured"
def test_unreachable_skipped(): ...               # transport raises ConnectError → status "skipped", note "model unreachable"
def test_request_cap_marks_rest_unreviewed():
    files = [ChangedFile(f"f{i}.py", None, {1: "eval(x)"}, "eval(x)\n") for i in range(40)]
    res = security_findings(files, client(max_requests=30), SEC, LLM, Redactor([]), FILTER)
    assert transport_calls() == 30 and res.status == "partial" and len(res.unreviewed) == 10
```

  Also, in `tests/test_review.py`: `test_model_down_does_not_fail_job`. With no secrets and an unreachable model, `run_review` returns 0 and the summary contains `Security check skipped: model unreachable`.

- [ ] **Step 2: Run `pytest tests/checks/test_security.py tests/test_review.py -v`.** Expected: FAIL.
- [ ] **Step 3: Implement `security.py` and wire it into `run_checks`.**
- [ ] **Step 4: Run the full suite.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: LLM security review check"`

---

### Task 9: Full-scan mode and reports

**Files:**
- Create: `src/airgap_pr_agent/fullscan.py`, `src/airgap_pr_agent/report.py`, `src/airgap_pr_agent/templates/report.html.j2`
- Modify: `src/airgap_pr_agent/cli.py` (`scan` subcommand), `templates/gitlab/pr-agent.gitlab-ci.yml` (scan job)
- Test: `tests/test_fullscan.py`, `tests/test_report.py`, `tests/test_templates.py`

**Interfaces:**
- **Consumes:** `run_gitleaks` and `secret_findings(..., changed=None, ...)` (Task 3); `tracked_files` and `whole_files` (Task 2); `non_english_findings` (Task 6); `security_findings` (Task 8); `LLMClient.from_env(..., max_requests=cfg.llm.max_requests_full_scan)` (Task 7).
- **Produces:**
  - `def run_full_scan(repo: Path, cfg: Config, llm, gitleaks_bin: str, out_dir: Path, history: bool) -> int`.
  - In `report.py`: `write_json(results: list[CheckResult], path: Path)`, `write_html(results, path: Path, repo_name: str)` and `write_sarif(results, path: Path)` (SARIF 2.1.0, `ruleId = f"{check}/{rule or title}"`, and `region.startLine` when the line is known).
  - The CLI: `scan [--repo .] [--out-dir pr-agent-report] [--history]`.
- **Outputs:**
  - Always `report.json` and `report.html`. `report.sarif` only when `cfg.full_scan.sarif`.
  - Print a one-line count per check to stdout.
  - Exit `1` if there are secrets and `cfg.full_scan.fail_on_secrets`; otherwise `0`. Errors exit `3`, as in `review`.
- **Secrets mode:** `"dir"` normally. `--history` runs `"dir"` and `"history"`, then dedupes by fingerprint.

- [ ] **Step 1: Write the failing tests:**
  - `test_writes_json_and_html_not_sarif_by_default`
  - `test_sarif_when_enabled`: the SARIF file parses, `version == "2.1.0"`, and it has one result per finding
  - `test_html_escapes_content`: a finding whose message contains `<script>alert(1)</script>` → the HTML contains `&lt;script&gt;` and not `<script>alert`
  - `test_reports_never_contain_raw_secret` (`requires_gitleaks`): a repo with a token; the raw value is absent from every output file
  - `test_exit_1_on_secrets_and_0_when_fail_disabled` (`requires_gitleaks`)
  - `test_history_flag_finds_removed_secret` (`requires_gitleaks`)
  - `test_excluded_paths_skip_language_check`: a `vendor/` file containing Chinese → no non-English findings
  - `test_gitlab_template_scan_job`: `pr-agent-full-scan` has `script == ["pr-agent scan --out-dir pr-agent-report"]`, `artifacts.when == "always"`, `artifacts.paths == ["pr-agent-report/"]`, a `$CI_PIPELINE_SOURCE == "schedule"` rule, and a `"web"` rule with `when: manual` and `allow_failure: true`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement it.**
  - The HTML template is a standalone page with inline CSS, grouped by check → severity → file. The Jinja2 `Environment` has `autoescape=True`.
  - Full scan runs non-English and security over `whole_files(repo, [p for p in tracked_files(repo) if filter allows])`. Binary files are skipped (NUL byte in the first 8 KB).
- [ ] **Step 4: Run the full suite.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: full-repo scan with JSON/HTML/SARIF reports"`

---

### Task 10: Azure DevOps adapter and pipeline template

**Files:**
- Create: `src/airgap_pr_agent/platforms/azure.py`, `templates/azure/pr-agent.yml`
- Modify: `src/airgap_pr_agent/cli.py` (`TF_BUILD` → Azure)
- Test: `tests/platforms/test_azure.py`, `tests/test_templates.py`

**Interfaces:**
- **Consumes:** `Platform`, `Thread`, `PlatformError`, `LogOnlyPlatform` (Tasks 4–5); `merge_base` (Task 2).
- **Produces:**
  - `def refs_from_repo(repo: Path) -> DiffRefs`. ADO PR builds check out a merge commit, so `head = HEAD^2` and `base = merge_base(HEAD^1, HEAD^2)`.
  - `class AzurePlatform(collection_uri: str, project: str, repo_id: str, pr_id: str, token: str, refs: DiffRefs, transport=None)`, which implements `Platform`.
  - `classmethod from_env(env, repo: Path) -> AzurePlatform | None`. It returns `None` if `SYSTEM_ACCESSTOKEN` is unset. It uses `SYSTEM_COLLECTIONURI`, `SYSTEM_TEAMPROJECTID`, `BUILD_REPOSITORY_ID` and `SYSTEM_PULLREQUEST_PULLREQUESTID`.
- **API version:** read from `PR_AGENT_ADO_API_VERSION`, default `6.0`. Azure DevOps Server 2019 needs `5.0`.
- **API calls** (`Authorization: Bearer <token>`, `api-version` as above, base `{collection}{project}/_apis/git/repositories/{repo}/pullRequests/{pr}`):

| Operation | Call |
|---|---|
| Head check | `GET {base}` → `lastMergeSourceCommit.commitId` must equal `refs.head` |
| List | `GET {base}/threads` → `value[]`: `id`; `comments[0].content`/`.id`; resolved = `status in ("fixed","closed","wontFix","byDesign")` |
| Post inline | `POST {base}/threads` with `{"comments": [{"parentCommentId": 0, "content": body, "commentType": 1}], "status": "active", "threadContext": {"filePath": "/" + path, "rightFileStart": {"line": n, "offset": 1}, "rightFileEnd": {"line": n, "offset": 1}}}` |
| Resolve | `PATCH {base}/threads/{id}` with `{"status": "fixed"}` or `{"status": "active"}` |
| Summary (new) | `POST {base}/threads` without `threadContext`, with `"status": "closed"`, so it never counts as an unresolved comment under a comment-resolution policy |
| Summary (update) | `PATCH {base}/threads/{id}/comments/{commentId}` with `{"content": body}` |

- [ ] **Step 1: Write the failing tests:**
  - `test_refs_from_merge_commit(git_repo)`: build main + feature, merge `--no-ff` → `head == feature tip` and `base == merge-base`
  - `test_list_threads_maps_status`
  - `test_post_inline_thread_context`: exact JSON as in the table
  - `test_can_post_inline_false_when_head_moved`
  - `test_set_resolved_patch`
  - `test_summary_post_closed_then_patch_comment`
  - `test_from_env_none_without_token`
  - `test_api_version_env_override`: with `PR_AGENT_ADO_API_VERSION=5.0`, every request URL has `api-version=5.0`
  - `test_cli_auto_detects_azure`
  - `test_azure_template`: YAML parameters `image`, `pool`, `mode` (`review`|`scan`), `history` (bool, default false); job `container: ${{ parameters.image }}`; `checkout: self` with `fetchDepth: 0`; the script step env maps `SYSTEM_ACCESSTOKEN: $(System.AccessToken)` and `LLM_API_KEY: $(LLM_API_KEY)`; scan mode publishes `pr-agent-report` as a pipeline artifact with `condition: always()`
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement the adapter and the template.**
- [ ] **Step 4: Run the full suite.** Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat: Azure DevOps adapter and pipeline template"`

---

### Task 11: Offline packaging, bundle, rollout docs

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `requirements.lock`, `requirements-dev.lock`, `scripts/fetch-gitleaks.sh`, `scripts/build-bundle.sh`, `vendor/gitleaks-8.21.2.sha256`, `docs/rollout.md`, `README.md`

**Interfaces:**
- **Consumes:** the whole package (Tasks 1–10).
- **Produces:**
  - the image `pr-agent` (entrypoint unset, `pr-agent` on `PATH`, non-root user, gitleaks at `/usr/local/bin/gitleaks`);
  - the bundle `dist/pr-agent-bundle-<version>-linux-x86_64.tar.gz` with `wheels/`, `bin/gitleaks` and `install.sh`.

- [ ] **Step 1: Lock the dependencies.**
  - Run `pip-compile --generate-hashes -o requirements.lock pyproject.toml`.
  - Run `pip-compile --generate-hashes --extra dev -o requirements-dev.lock pyproject.toml`.
- [ ] **Step 2: Vendor gitleaks.**
  - Write `scripts/fetch-gitleaks.sh`, to run on a connected machine. It downloads `gitleaks_8.21.2_linux_x64.tar.gz` from the GitHub release into `vendor/` and verifies it with `sha256sum -c vendor/gitleaks-8.21.2.sha256`.
  - Fill the `.sha256` file from the release's `checksums.txt` and commit it. The tarball itself is git-ignored.
  - For an air-gapped build, the tarball is copied into `vendor/` by hand.
- [ ] **Step 3: Write the `Dockerfile`.**
  - `ARG BASE_IMAGE=python:3.12-slim@sha256:<digest>`. Resolve the digest once with `docker buildx imagetools inspect python:3.12-slim` and commit it.
  - `ARG PIP_INDEX_URL` (optional, for an internal mirror).
  - Stages:
    - `deps`: `pip install --require-hashes -r requirements.lock`, gitleaks verified and extracted, and `apt-get install git`.
    - `test`: dev deps; run `PR_AGENT_REQUIRE_GITLEAKS=1 pytest -q`.
    - `final`: copy the venv and gitleaks, `useradd -u 10001 agent`, and `git config --system --add safe.directory '*'` (CI checkouts belong to other users).
- [ ] **Step 4: Verify the build and the tests in the image.**
  - Run: `docker build --target test .` Expected: all tests pass, and **none are skipped for gitleaks**.
  - Run: `docker build -t pr-agent:dev .` Expected: success.
- [ ] **Step 5: Verify it works with no network.**
  - Create a sample repo containing a commit with `token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"` and a `// 获取用户` comment.
  - Run: `docker run --rm --network none -v "$PWD/sample:/repo" pr-agent:dev pr-agent review --platform local --repo /repo --base <base>`
  - Expected: exit code 1. Stdout shows a masked secret comment, a non-English comment, `Security check skipped: model not configured` and `Merge blocked`. No network errors.
- [ ] **Step 6: Write `scripts/build-bundle.sh`.**
  - It runs `pip wheel --require-hashes -r requirements.lock -w wheels/` plus the project wheel, adds `bin/gitleaks`, and adds `install.sh`.
  - `install.sh` creates a venv and runs `pip install --no-index --find-links wheels airgap-pr-agent`. It prints `export GITLEAKS_BIN=<dir>/bin/gitleaks`.
  - Verify it: unpack the bundle into a temp dir, run `install.sh`, then run `pr-agent --help`. Expected: help text; nothing is fetched.
- [ ] **Step 7: Write `docs/rollout.md`.**
  - **Building and importing the image:** with a mirror, or as a tarball via `docker save`/`docker load`.
  - **GitLab setup:**
    - group variables: `PR_AGENT_GITLAB_TOKEN` (a project/group access token with `api` scope, masked) and `LLM_BASE_URL`/`LLM_API_KEY` (masked)/`LLM_MODEL`;
    - the `include:` snippet;
    - turning on "Pipelines must succeed";
    - the recommended `workflow:rules` snippet for MR pipelines without duplicate branch pipelines;
    - a note on forks.
  - **Azure DevOps setup:**
    - grant the build service "Contribute to pull requests";
    - a variable group;
    - the `extends`/template usage;
    - a required build-validation policy.
  - **Config reference:** every `.pr-agent.yml` key with its default.
  - **How to allowlist a false-positive secret.**
  - **The acceptance checklist**, copied from the spec's "What success looks like":
    - a real MR with a secret and a Chinese comment → 2 inline comments, a summary, and the merge blocked;
    - fixing them → the pipeline passes and the threads resolve;
    - a full scan of a large real repo produces a report;
    - **time a typical MR** and record it;
    - the same on Azure DevOps;
    - with the model endpoint stopped, the MR still passes, with the skipped note.
  - **The Azure DevOps Server 2019 note:** the thread APIs used also exist at `api-version=5.0`. On 2019, set `PR_AGENT_ADO_API_VERSION=5.0`. The override is in Task 10.
- [ ] **Step 8: Write the README.** Cover what it does, the two CLI commands, exit codes, and a link to `docs/rollout.md`.
- [ ] **Step 9: Commit:** `git commit -m "build: offline image, wheel bundle and rollout docs"`
