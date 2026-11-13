# Rolling out pr-agent

This guide covers getting pr-agent into an air-gapped network and turning it on
for GitLab and Azure DevOps. It ends with the acceptance checklist for the
rollout.

pr-agent ships in two forms:

| Form | Use it for | Where it comes from |
| --- | --- | --- |
| Container image | Docker-based GitLab runners and Azure DevOps container jobs | `ghcr.io/<owner>/airgaped-pr-agent:<tag>` (linux/amd64, linux/arm64), or built from this repo |
| Offline bundle | Shell runners and self-hosted agents without Docker | `pr-agent-bundle-<version>-linux-x86_64.tar.gz` on the GitHub release |

Both contain everything the agent needs: Python dependencies, gitleaks 8.30.1
and its rules. Nothing is downloaded at runtime. The only network calls are to
your platform API and to `LLM_BASE_URL`.

## 1. Getting the image into the internal registry

### From the published image (recommended)

On a connected machine, pull the release for the architecture your runners use.
Use the version tag rather than `latest`, so you know what you imported.

```sh
docker pull --platform linux/amd64 ghcr.io/<owner>/airgaped-pr-agent:v0.1.0
docker save ghcr.io/<owner>/airgaped-pr-agent:v0.1.0 -o pr-agent-v0.1.0.tar
sha256sum pr-agent-v0.1.0.tar > pr-agent-v0.1.0.tar.sha256
```

Move the tarball and its checksum across the air gap. Then, inside the network:

```sh
sha256sum -c pr-agent-v0.1.0.tar.sha256
docker load -i pr-agent-v0.1.0.tar
docker tag ghcr.io/<owner>/airgaped-pr-agent:v0.1.0 registry.internal/devtools/pr-agent:0.1.0
docker tag ghcr.io/<owner>/airgaped-pr-agent:v0.1.0 registry.internal/devtools/pr-agent:1
docker push registry.internal/devtools/pr-agent:0.1.0
docker push registry.internal/devtools/pr-agent:1
```

If the connected side can reach the internal registry through a mirror or
proxy, skip `save`/`load` and run `docker pull`, `docker tag` and `docker push`
directly.

### Building from source

The build fetches nothing at runtime, but it does need, at build time:

- Python packages: from PyPI, or from an internal mirror via `--build-arg PIP_INDEX_URL=...`. Every package is checked against the hashes in `requirements*.lock`.
- `git`: from the base image's Debian apt sources, or your apt mirror.
- The base image `python:3.12-slim`, pinned by digest in the `Dockerfile`. Override it with `--build-arg BASE_IMAGE=registry.internal/library/python:3.12-slim@sha256:...`.
- The gitleaks tarballs in `vendor/`. On a connected machine, run `scripts/fetch-gitleaks.sh`. In an air-gapped build, copy `gitleaks_8.30.1_linux_x64.tar.gz` and `gitleaks_8.30.1_linux_arm64.tar.gz` into `vendor/` by hand. The build checks them against `vendor/gitleaks-8.30.1.sha256` and fails on a mismatch.

```sh
scripts/fetch-gitleaks.sh
docker build --target test .                      # full test suite, gitleaks mandatory
docker build -t registry.internal/devtools/pr-agent:1 .
docker push registry.internal/devtools/pr-agent:1
```

The image:

- has no `ENTRYPOINT`, and has `pr-agent` on `PATH`;
- runs as a non-root user (uid 10001);
- has gitleaks at `/usr/local/bin/gitleaks`;
- trusts every checkout directory (`git config --system safe.directory '*'`), because CI checkouts belong to other users.

## 2. Non-container runners: the offline bundle

You need Linux x86_64 (glibc), Python 3.12 and `git` on the runner.

```sh
sha256sum -c pr-agent-bundle-0.1.0-linux-x86_64.tar.gz.sha256
tar -xzf pr-agent-bundle-0.1.0-linux-x86_64.tar.gz -C /opt
/opt/pr-agent-bundle-0.1.0-linux-x86_64/install.sh /opt/pr-agent
```

`install.sh` creates a virtualenv from the bundled wheels only (`pip install
--no-index`). Each wheel is checked against the bundled `requirements.lock`.
At the end it prints the two lines to add to the runner's environment:

```sh
export PATH=/opt/pr-agent/bin:$PATH
export GITLEAKS_BIN=/opt/pr-agent-bundle-0.1.0-linux-x86_64/bin/gitleaks
```

To build the bundle yourself, run `scripts/fetch-gitleaks.sh` and then
`scripts/build-bundle.sh` on a connected machine with Python 3.12. The output
goes to `dist/`.

## 3. Full clone history is required

pr-agent scans the commits between the MR's base and head. If the base commit
is not in the clone, the secrets check **fails closed**: the job exits with
code 3. It does not pass silently. Both templates already set this:

- GitLab: `GIT_DEPTH: "0"`.
- Azure DevOps: `fetchDepth: 0` on the checkout step.

Don't override these in your project. A shallow clone, or the default
`fetchDepth` of newer Azure DevOps pipelines, will make every review fail.

## 4. GitLab setup

### Variables

Add these at the group level (**Settings > CI/CD > Variables**), so every
project inherits them. Don't mark them **Protected**: MR source branches are
usually unprotected, and protected variables don't reach their pipelines.

| Variable | Value | Flags |
| --- | --- | --- |
| `PR_AGENT_GITLAB_TOKEN` | A project or group access token with the `api` scope and the Developer role, so it can post comments and resolve threads | Masked |
| `LLM_BASE_URL` | The OpenAI-compatible endpoint, including `/v1`, for example `https://llm.internal/v1` | |
| `LLM_API_KEY` | The endpoint's API key | Masked |
| `LLM_MODEL` | The model name the endpoint serves | |
| `PR_AGENT_IMAGE` | Optional. Your internal image path, for example `registry.internal/devtools/pr-agent:1` | |

If `PR_AGENT_GITLAB_TOKEN` is missing, the job still runs and still blocks on
secrets. It prints the findings to the job log instead of posting them, and
logs a warning. If `LLM_BASE_URL` or `LLM_API_KEY` is missing, the security
check is skipped and the summary says so.

### Include the template

Put `templates/gitlab/pr-agent.gitlab-ci.yml` in a shared project, for example
`devtools/pr-agent`. Then include it from each project's `.gitlab-ci.yml`:

```yaml
include:
  - project: devtools/pr-agent
    ref: v0.1.0
    file: templates/gitlab/pr-agent.gitlab-ci.yml
```

This adds two jobs to the `test` stage. If your pipeline defines `stages:`, it
must include `test`.

- `pr-agent-review` runs on merge request pipelines.
- `pr-agent-full-scan` runs on scheduled pipelines. In a pipeline started from **Run pipeline**, the job is `when: manual`: after starting the pipeline, press the job's play button to run the scan. It writes `pr-agent-report/` as a job artifact.

### Choosing the image

The template defaults `PR_AGENT_IMAGE` in its job-level `variables:`. A
top-level `variables:` block in your `.gitlab-ci.yml` will **not** override it,
because job-level YAML variables take precedence over global ones. Use one of
these instead:

- a CI/CD variable `PR_AGENT_IMAGE` in project or group settings (the simplest option, and it covers every project in the group);
- or a job-level override in the including project:

  ```yaml
  pr-agent-review:
    variables:
      PR_AGENT_IMAGE: registry.internal/devtools/pr-agent:0.1.0
  pr-agent-full-scan:
    variables:
      PR_AGENT_IMAGE: registry.internal/devtools/pr-agent:0.1.0
  ```

### Block merges

In each project, go to **Settings > Merge requests > Merge checks** and turn on
**Pipelines must succeed**. The agent exits 1 when it finds a secret, which
fails the pipeline and blocks the merge. Security and language findings never
fail it.

### MR pipelines without duplicate branch pipelines

The review job only runs in merge request pipelines. To stop every push to an
MR branch from also starting a branch pipeline, add this `workflow:rules` block:

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule" || $CI_PIPELINE_SOURCE == "web"
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS
      when: never
    - if: $CI_COMMIT_BRANCH
```

Scheduled and manually started (**Run pipeline**) pipelines are branch
pipelines. The second rule keeps them, even on a branch that has an open MR.
Without that rule, the `when: never` line would drop them there too.

### Full scans

Create a pipeline schedule (**Build > Pipeline schedules**) on the default
branch, for example weekly. The scan exits 1 when it finds secrets, so the
scheduled pipeline shows as failed. Set `full_scan.fail_on_secrets: false` in
`.pr-agent.yml` if you'd rather it report without failing.

The scan writes `pr-agent-report/` into the checkout as uid 10001, so that uid must be able to write there. The Docker executor's default checkout (`umask 0000`) allows it. If your runner sets `FF_DISABLE_UMASK_FOR_DOCKER_EXECUTOR`, check that the scan job can still write its reports.

### Forks

MR pipelines from forks run in the fork's project, with the fork's CI/CD
variables. The parent group's masked token and LLM key aren't available there.
The job still runs the secrets check and still blocks the merge. It can't post
comments, though: findings go to the job log. The security check is skipped. A
fork author can also edit the fork's `.gitlab-ci.yml`. For internal work, have
developers push branches to the main project rather than using forks.

## 5. Azure DevOps setup

You need a self-hosted Linux agent with Docker, able to pull the image from
your registry. Run `docker login` on the agent host if the registry needs
authentication.

### Permissions

In **Project settings > Repositories > (repository) > Security**, find
**`<Project>` Build Service (`<Collection>`)** and set **Contribute to pull
requests** to **Allow**. The agent posts and resolves PR threads with
`System.AccessToken`.

### Variable group

In **Pipelines > Library**, create a variable group, for example `pr-agent`:

| Variable | Value |
| --- | --- |
| `LLM_BASE_URL` | `https://llm.internal/v1` |
| `LLM_MODEL` | the model name |
| `LLM_API_KEY` | the key; click the lock to make it secret |
| `PR_AGENT_ADO_API_VERSION` | only for Azure DevOps Server 2019; see below |

Secret variables aren't exposed to scripts automatically. The template maps
`LLM_API_KEY` into the step environment for you.

### Pipeline

Keep `templates/azure/pr-agent.yml` in a shared repository, for example
`devtools/pr-agent`. Then create a pipeline in each repository:

```yaml
trigger: none          # PR runs come from the build validation policy

resources:
  repositories:
    - repository: pr-agent
      type: git
      name: devtools/pr-agent
      ref: refs/tags/v0.1.0

variables:
  - group: pr-agent

jobs:
  - template: templates/azure/pr-agent.yml@pr-agent
    parameters:
      image: registry.internal/devtools/pr-agent:1
      pool: { name: internal-linux }
      mode: review
```

For a scheduled full scan, create a second pipeline with `mode: scan` and a
`schedules:` trigger. Add `history: true` to scan the whole history as well. The
scan publishes `pr-agent-report` as a pipeline artifact. Scan steps don't get
`System.AccessToken`, because they never call the platform API.

The template starts the container with `--user 0:0`. Azure's container-job
setup needs root, because it adds a user that matches the agent's uid. It then
runs the steps as that user, not as root.

### Require it on PRs

Go to **Project settings > Repos > Branches**, open the target branch's
**Branch policies**, and add a **Build validation** policy:

- Pipeline: the review pipeline.
- Trigger: Automatic.
- Policy requirement: **Required**.

Review mode only works in a PR validation build. Azure Repos ignores YAML `pr:`
triggers, so the policy is what runs it.

### Azure DevOps Server 2019

The thread APIs the agent uses also exist at `api-version=5.0`. On Server 2019,
set `PR_AGENT_ADO_API_VERSION=5.0`, as a pipeline variable or in the variable
group. Server 2020 and later need nothing: the default is `6.0`.

## 6. Configuration reference (`.pr-agent.yml`)

The file is optional and lives in the repository root. Whatever you put there
is deep-merged over the built-in defaults below. Lists replace the default list
rather than extending it. Unknown keys are an error (exit 3).

| Key | Default | Meaning |
| --- | --- | --- |
| `checks.secrets` | `true` | Run the gitleaks secrets check. This is the only check that blocks. |
| `checks.non_english` | `true` | Flag non-English comments and string literals. |
| `checks.security` | `true` | Run the LLM security review. |
| `paths.include` | `["**"]` | Globs of files to check. |
| `paths.exclude` | vendored, generated and lock files: `**/vendor/**`, `**/node_modules/**`, `**/third_party/**`, `**/dist/**`, `**/build/**`, `**/*.min.js`, `**/*.min.css`, `**/*_pb2.py`, `**/*.pb.go`, `**/*.generated.*`, `**/package-lock.json`, `**/yarn.lock`, `**/pnpm-lock.yaml`, `**/poetry.lock`, `**/Pipfile.lock`, `**/Cargo.lock`, `**/go.sum`, `**/composer.lock`, `**/Gemfile.lock`, `**/*.lock` | Globs to skip for the language and security checks. The secrets check still scans them. |
| `security.min_severity` | `medium` | Lowest severity to report: `low`, `medium` or `high`. |
| `security.context_lines` | `20` | Lines of context sent to the model around each change. |
| `non_english.min_words` | `4` | Shorter texts are ignored. |
| `non_english.min_confidence` | `0.7` | Language-detector confidence needed to flag a text. |
| `non_english.exclude` | `**/locale/**`, `**/locales/**`, `**/i18n/**`, `**/*.po`, `**/*.pot`, `**/*.??.resx`, `**/*.??-??.resx`, `**/testdata/**`, `**/fixtures/**`, `**/__fixtures__/**` | Extra globs skipped by the language check only. |
| `secrets.allowlist` | `[]` | False-positive secrets to ignore. See section 7. |
| `llm.prompt_token_budget` | `8000` | Approximate token budget for each request. |
| `llm.concurrency` | `2` | Parallel requests to the model. |
| `llm.timeout_seconds` | `120` | Timeout for each request. |
| `llm.retries` | `2` | Retries for each failed request. |
| `llm.max_requests_per_mr` | `30` | Cap on requests for each review. |
| `llm.max_requests_full_scan` | `300` | Cap on requests for each full scan. |
| `llm.json_mode` | `false` | Send `response_format: json_object`, for endpoints that support it. |
| `full_scan.fail_on_secrets` | `true` | `pr-agent scan` exits 1 when it finds secrets. |
| `full_scan.sarif` | `false` | Also write `report.sarif`. |

Environment variables:

| Variable | Used for |
| --- | --- |
| `LLM_BASE_URL` | OpenAI-compatible base URL, including `/v1`. |
| `LLM_API_KEY` | The endpoint's key. Without it, or without the URL, the security check is skipped. |
| `LLM_MODEL` | The model name. |
| `PR_AGENT_GITLAB_TOKEN` | GitLab API token. |
| `SYSTEM_ACCESSTOKEN` | Azure DevOps token, mapped by the template. |
| `GITLEAKS_BIN` | Path to gitleaks. Defaults to `gitleaks` on `PATH`; the image sets `/usr/local/bin/gitleaks`. |
| `PR_AGENT_ADO_API_VERSION` | Azure DevOps REST API version. Defaults to `6.0`. |

## 7. Allowlisting a false-positive secret

The `secrets.allowlist` in `.pr-agent.yml` is the **only** way to silence an
individual secret finding. The agent deliberately ignores a repository's own
`.gitleaks.toml`, its `.gitleaksignore` and inline `gitleaks:allow` comments.
Because the allowlist lives in the repository, every change to it shows up in
the MR diff, where a human reviewer sees it.

The only other way to stop a secret blocking is `checks.secrets: false` in
`.pr-agent.yml`. That turns the secret gate off entirely for the repository.
It is just as visible in the MR diff, and reviewers should treat it the same
way.

Besides the upstream gitleaks rules, the bundled config adds three rules:

- `hardcoded-password` catches a quoted literal of 6+ characters assigned to a key that ends in a credential word: `password`, `passwd`, `secret`, `token`, `api_key`, `secret_key`, `private_key`, `access_key`, `signing_key`, `encryption_key`, `master_key`, `auth_key`, `pwd` or `pass`. An environment suffix such as `_PROD` or `_staging` is allowed after the word. Examples: `password = "Hunter2!prod"`, `String dbPassword = "..."`, `"client_secret": "..."` and `DB_PASSWORD_PROD = "..."`. Keys that only contain the word, such as `tokenizer`, `token_url` or `password_reset_url`, don't match.
- `hardcoded-password-unquoted` catches the same kind of key with an unquoted value. It only applies in config files: `.env`, `.env.*`, `*.env`, `.envrc`, YAML, `.properties`, `.ini`, `.cfg`, `.conf` and `.toml`. Examples: `DB_PASSWORD=Hunter2!prod` and `password: Hunter2!prod`. Shell command substitution such as `export GITHUB_TOKEN=$(security find-generic-password -s gh -w)` (or the backtick form) is a lookup, not a value, and is not reported.
- `connection-string-credentials` catches the password in a URL such as `postgres://app:S3cretPass@db/x` or `redis://:S3cretPass@cache:6379`.

These rules don't report values that are clearly not secrets:

- **Placeholders and templates:** anything containing `changeme`, `example`, `placeholder`, `dummy` or `redacted`; `xxxx` or `****`; `${VAR}`, `{{ var }}`, `<your-password>`, `%(name)s`, `$VAR` (including `$K8S_SECRET`) and `$(Var)`. These exceptions also apply to the upstream `generic-api-key` rule.
- **Names rather than values:** environment variable names (`OPENAI_API_KEY`, `S3_SECRET_KEY`, `K8S_SERVICE_TOKEN`, `OAUTH2_CLIENT_SECRET`), words joined by `-`, `_`, `.` or `/` (`db-credentials`, `bert-base-uncased`, `monitoring/basic-auth`), single or CamelCase words (`Authorization`, `SecretsManager`), absolute paths, URLs and ARNs, and cipher or algorithm names (`aes-256-gcm`, `hmac-sha256`, `ed25519`, `sha512`). Every word must be letters only, except that each segment of an env var name may hold one run of up to two digits.
- **Key files and references:** values starting with `~/`, `./` or `../` (`~/.ssh/id_rsa`), key and certificate file names ending in `.pem`, `.key`, `.crt`, `.cer`, `.p12`, `.pfx`, `.jks`, `.keystore` or `.der` (`certs/server-2024.pem`), and `classpath:`/`file:`/`vault:` references (`vault:secret/data/app#password`). These must consist of path characters only (letters, digits, `_`, `.`, `/`, `-`; also `#` in vault references and `:` or `\` in Windows key-file paths such as `C:\certs\tls.pfx`), so `file:Hunter2!prod` is still reported.
- **In URLs:** well-known development passwords (`postgres`, `root`, `guest`, `admin`, `test`, `password`, ...) and any credentials on `localhost`, `127.0.0.1` or `[::1]`.

Random tokens such as `QX7Z2LMPK4R8T`, `ABCD_EFGH1234_IJKL5678`, `$UPERS3CRET9` or `hunter2-prod` are still reported. A value that is shaped exactly like an env var name, such as `HUNTER2_PROD`, is treated as a name. These name exceptions apply only to the bundled rules: upstream `generic-api-key` behaves exactly as in stock gitleaks, false positives such as `password_hasher = "argon2id-v19"` and `encryption_key = "chacha20-poly1305"` included.

As a result, a password made only of letters is not caught by the bundled rules, whether it is a single word (`Sunshine`) or words joined by dashes (`correct-horse-battery-staple`).

The same secret can be found twice on one line. In that case:

- If a specific upstream rule also matched (an AWS or Stripe key, for example), only the upstream finding is shown.
- If the upstream rule is `generic-api-key`, gitleaks itself keeps the bundled rule's finding and drops the generic one.

Either way, one secret on one line produces one comment.

Each secret comment ends with the finding's fingerprint:

> If this is a false positive, allowlist fingerprint `3f9c0a1b2c3d4e5f`.

Copy it into the allowlist:

```yaml
secrets:
  allowlist:
    # Test fixture key, not a real credential (reviewed in !123)
    - fingerprint: 3f9c0a1b2c3d4e5f
    # Everything under the fake-credentials test fixtures
    - path: "tests/fixtures/fake-creds/**"
```

- A `fingerprint` entry matches one secret value, found by one rule, in one file. It stops matching if the value or the file changes.
- A `path` entry is a glob, and it silences every secret in matching files. Use it sparingly.
- An entry with both a `fingerprint` and a `path` must match both.

If the secret is real, an allowlist entry is the wrong fix. Rotate the
credential and remove it from the code.

## 8. Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No blocking findings. Security and language findings never block. |
| `1` | Secrets found. |
| `3` | Internal error: gitleaks failed, the config is invalid, a git ref is missing (shallow clone), or the platform API failed. The agent fails closed. |

## 9. Acceptance checklist

Run through this list before announcing the rollout. Record the results here.

- [ ] **GitLab, secrets and language.** Open a real MR that adds `password = "Hunter2!prod"` and a comment `// 获取用户信息`. The pipeline shows two inline comments on those lines and one summary comment. The pipeline fails, and the MR can't be merged.
- [ ] **GitLab, fix.** Fix both and push. The pipeline passes, and the agent resolves its old threads.
- [ ] **Full scan.** A full scan of a large real repository finishes and produces a report a lead can read and triage. Repository: ______; duration: ______.
- [ ] **Timing.** Time the `pr-agent-review` job on a typical MR, with the model configured. Files changed: ______; job duration: ______.
- [ ] **Azure DevOps.** Repeat the first two steps on an Azure DevOps PR under the build validation policy.
- [ ] **Model down.** Stop the model endpoint, or point `LLM_BASE_URL` at a dead address. The MR still passes, and the summary notes that the security check was skipped.
