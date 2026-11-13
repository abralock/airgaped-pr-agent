# airgap-pr-agent

`pr-agent` reviews merge requests (GitLab) and pull requests (Azure DevOps
Server) inside an air-gapped network. It runs as a CI job, posts inline
comments and a single summary comment, and blocks the merge when it finds a
hardcoded secret.

It runs three checks on the changed lines:

| Check | How | Blocks the merge? |
| --- | --- | --- |
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 with bundled rules. Deterministic: the model never judges a secret. Every secret gitleaks finds, whether added by the MR or already in a changed file, is masked (`AKIA****`) in comments, logs, reports and model prompts. | **Yes** |
| Non-English text | Comments and string literals, using an offline language detector. | No, advisory |
| Security review | An OpenAI-compatible model on your network (`LLM_BASE_URL`). If the model is down or not configured, the check is skipped and the summary says so. | No, advisory |

Nothing is downloaded at runtime. The only network calls go to your GitLab or
Azure DevOps API and to `LLM_BASE_URL`.

## Quick start

The image is published at `ghcr.io/<owner>/airgaped-pr-agent` for linux/amd64
and linux/arm64. Import it into your internal registry first; see
[docs/rollout.md](docs/rollout.md).

Try it on a local repository. This posts nothing; findings are printed:

```sh
docker run --rm --network none -v "$PWD:/repo" ghcr.io/<owner>/airgaped-pr-agent:latest \
  pr-agent review --platform local --repo /repo --base origin/main
```

In CI, include the ready-made templates:

- GitLab: `templates/gitlab/pr-agent.gitlab-ci.yml`
- Azure DevOps: `templates/azure/pr-agent.yml`

For runners without Docker, use the offline wheel bundle
`pr-agent-bundle-<version>-linux-x86_64.tar.gz` from the GitHub release. Run
its `install.sh`.

## CLI

```
pr-agent review [--repo DIR] [--platform auto|gitlab|azure|local] [--base REF] [--head REF]
pr-agent scan   [--repo DIR] [--out-dir DIR] [--history]
```

- `review` checks the MR/PR diff. With `--platform auto` (the default), it detects GitLab CI or Azure Pipelines from the environment, posts inline comments, keeps one summary comment up to date, and resolves its own threads once the findings are fixed. With `--platform local`, it prints the findings for `--base`..`--head` (default `HEAD`).
- `scan` checks the whole repository and writes `report.json` and `report.html` (plus `report.sarif` if enabled) to `--out-dir` (default `pr-agent-report`). `--history` also scans every commit for secrets.

Configuration lives in an optional `.pr-agent.yml` in the repository root. See
the [config reference](docs/rollout.md#6-configuration-reference-pr-agentyml).

| Environment variable | Purpose |
| --- | --- |
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` | Model endpoint. The URL includes `/v1`. |
| `PR_AGENT_GITLAB_TOKEN` | GitLab token with the `api` scope. |
| `SYSTEM_ACCESSTOKEN` | Azure DevOps token, mapped by the template. |
| `GITLEAKS_BIN` | Path to gitleaks. The default is `gitleaks`. |
| `PR_AGENT_ADO_API_VERSION` | Azure DevOps API version. The default is `6.0`; use `5.0` for Server 2019. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No blocking findings. |
| `1` | Secrets found. The merge is blocked. |
| `3` | Internal error: gitleaks failure, bad config, missing git history, or a platform API error. The agent fails closed. |

## Development

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/pytest -q
scripts/fetch-gitleaks.sh && docker build --target test .   # suite in the image, gitleaks mandatory
```

The dependency locks are hash-pinned:

- `requirements.lock` and `requirements-dev.lock` are generated with `uv pip compile --generate-hashes --python-version 3.12 --python-platform linux`.
- `requirements-build.lock` is generated with `pip-compile --only-build-deps`.

The command for each one is in its file header.

See [docs/rollout.md](docs/rollout.md) for building, importing and rolling out.
