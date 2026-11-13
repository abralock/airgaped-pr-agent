# Air-gapped MR/PR Review Agent — Design

**Date:** 2026-11-13
**Status:** Draft, awaiting approval

Labels used below: **[user]** means the user decided it. **[my call]** means Claude decided it during brainstorming; the user can still override these.

---

## 1. Why this exists

Senior developers manually review every merge request. Much of that time goes to mechanical checks a person shouldn't have to make:

- security problems in the code
- secrets hardcoded into the source (passwords, API keys, tokens, connection strings)
- comments and string literals that are not in English, which company policy forbids

The agent takes over these checks so reviewers can focus on design and logic. It must run **entirely inside the company network**. The only AI it may use is the company's on-prem model, reached with a company `sk-...` API key **[user]**.

## 2. Goals

1. **MR/PR mode.** When a merge request (GitLab) or pull request (Azure DevOps) is opened or updated, scan **only the changed lines** **[user]** for:
   - security issues
   - hardcoded secrets
   - non-English text in **comments and string literals** **[user]**
2. **Inline feedback.** Post each finding as a comment on the exact changed line **[user]**.
3. **Merge gate.** **Block the merge when a secret is found** **[user]**. Security and non-English findings are advisory: they get comments but don't block **[my call, inferred from the user only naming secrets as blocking]**.
4. **Full-scan mode.** Scan an entire repository on demand, not just a diff **[user]**.
5. **Platforms.** Self-hosted GitLab is the primary target. Azure DevOps (on-prem Server) is also supported **[user]**.

### What success looks like

- A developer opens an MR containing `password = "Hunter2!prod"` and a comment `// 获取用户信息`. Within the pipeline run they see two inline comments on those lines, plus one summary comment. The pipeline fails and the MR can't be merged.
- They fix both and push. The pipeline passes, and the agent marks its old threads resolved.
- A full scan of a large real repo finishes and produces a report a lead can read and triage.
- Developers don't learn to ignore it. The volume of noise stays low.

## 3. Non-goals

- It does not replace human review, and it never approves an MR.
- It does not auto-fix code or push commits.
- It does not check identifiers (variable, function or class names) for English. Only comments and string literals are checked **[user]**.
- It does not scan dependencies or look up CVEs **[my call; SCA is a separate tool category]**.
- It is not a long-running service or webhook server **[my call, see §5]**.
- It makes no network calls outside the company network: no telemetry, no update checks, and no model or rule downloads at runtime.

## 4. Anti-goals (failures even if it "works")

- **A secret gets through because the model was slow, down or wrong.** Secret detection and blocking must be deterministic. They must never depend on the model.
- **The agent leaks the secret it found.** Comments, logs, reports and model prompts must show secrets masked (for example `Hunt****`), never in full.
- **Noise.** Duplicate comments on every push, or a flood of low-value "consider validating input" findings, will get the bot ignored or removed.
- **Blocking merges on the model's opinion.** Model findings are advisory only.
- **The pipeline is too slow.** A typical MR should add only a few minutes, not tens of minutes.

## 5. Constraints and decided "how"

### Runtime and packaging
- **Language:** Python 3.12 **[my call]**. Both platforms have mature Python API clients, it calls OpenAI-compatible endpoints easily, and it packages well offline.
- **Delivery:** a single self-contained container image, pushed to the company's internal registry **[my call; the user confirmed an internal registry and self-hosted runners/agents exist]**. All Python packages, rule sets, binaries and any language-ID data are baked into the image. Nothing is fetched at runtime.
- **Trigger:** a pipeline job, not a service **[my call]**.
  - GitLab: a reusable CI template that repos pull in with `include:`. It runs on `merge_request_event` pipelines.
  - Azure DevOps: a reusable YAML pipeline template, wired up as a build-validation policy on target branches.
- **Merge blocking** uses the platform's own gates. The job exits non-zero when a secret is found.
  - GitLab: the project setting "Pipelines must succeed"
  - Azure DevOps: a required build-validation policy

### Model access
- The on-prem model is assumed to expose an **OpenAI-compatible chat-completions API** **[my call, inferred from the `sk-` key format; the user didn't contradict it]**.
- Configuration comes from environment variables: `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`.
- The key lives in a masked/secret CI variable at group or project level. It never goes in a repo or in this conversation.
- The model's context window and capability are unknown. The agent must chunk its input, and these settings must be configurable:
  - maximum tokens per request
  - maximum requests per MR
  - timeouts

### Getting software into the network **[my call]**
- **Pinned and offline-buildable.** The image build pins every dependency (hashed Python requirements, a fixed gitleaks version, the base image by digest). It can be built either way:
  - against internal mirrors, if they exist, chosen with build args;
  - on a connected machine, with the result imported as an image tarball.
- **Testing.** Development and CI tests use recorded API fixtures and a fake OpenAI-compatible server. A short manual acceptance checklist covers real GitLab, real Azure DevOps and the real model endpoint before rollout. That checklist includes timing a typical MR.

### Pipeline wiring details **[my call]**
- **GitLab triggering.** The template uses `workflow:rules`-compatible `rules`, so it doesn't create duplicate branch and MR pipelines in projects that already run branch pipelines. The rollout docs tell teams to turn on MR pipelines.
- **Forks.** Fork-based MRs/PRs are assumed not to be used. If one appears, the agent can't post comments, because it has no token. It still fails the job when it finds secrets, and it prints its findings to the job log.

### Threat model for the gate **[user]**
The secret gate exists to **catch honest mistakes**. It doesn't have to stop someone deliberately getting around it. A developer can switch the check off in their own MR by editing `.pr-agent.yml` (including the allowlist), removing the include, or skipping CI. Those changes are visible in the MR diff, so the human reviewer can see them. No enforcement beyond that is in scope: no compliance pipelines, no reading config from the target branch, and no CODEOWNERS requirement.

### Platform and environment assumptions **[my call; the user doesn't know these and asked for defaults]**
- **GitLab:** design for **Free tier** features only, using REST API v4, plain `include:` templates and MR discussions with line positions. Target GitLab 15.0 or later. Use no Premium/Ultimate-only features. Don't emit GitLab's security-dashboard report format; optional SARIF is enough.
- **Azure DevOps Server:** target **2020 or later**, with REST `api-version=6.0`. If any API used isn't available on 2019, note it in the rollout docs.
- **Runners/agents:** assume **Linux, able to run containers.** That means the GitLab Docker or Kubernetes executor, and Azure DevOps Linux agents running container jobs. As a fallback for non-container runners, ship a plain Python wheel bundle (the app plus its dependencies, and a gitleaks binary) that runs with `python -m`.
- **Model endpoint:** assume an **OpenAI-compatible** `/v1/chat/completions` API. Start from conservative defaults, all overridable by env/config:
  - about 8k-token prompt budget per request
  - 2 concurrent requests per job
  - 120s timeout with 2 retries
  - at most 30 model requests per MR
  
  The client sits behind a small interface, so a different API shape can be added later.

### Platform credentials
- **GitLab:** `CI_JOB_TOKEN` can't post MR discussions. The agent needs a project or group access token with `api` scope, stored as a masked CI variable.
- **Azure DevOps:** the pipeline's `System.AccessToken`. The build service identity needs "Contribute to pull requests".

## 6. How each check works

### 6.1 Hardcoded secrets (blocking) **[my call]**
- **Detection:** deterministic only, using pattern rules plus entropy checks.
- **Engine:** an established open-source engine with a bundled rule set, rather than custom regexes. Gitleaks (a single binary) is the recommendation; Yelp `detect-secrets` (Python) is an acceptable alternative. Either way it's vendored into the image.
- **No model override.** The model can't dismiss a secret finding.
  - *Change from what we discussed in chat: earlier I suggested the model could weed out false alarms. Since a wrong model answer would let a real secret through, I've dropped that.*
- **False positives** are silenced by an allowlist in the repo config file (§7), referenced by finding fingerprint or path. Because the allowlist sits in the repo, any change to it is visible in the MR and gets reviewed by a human.
- **Masking:** every comment, log line and report shows the value masked.
- **Commit history in MR mode [my call].** Secrets are scanned in **every commit in the MR**, not only the final diff. A secret added and then deleted within the MR would otherwise still land in history, unless the MR is squashed.
  - If the secret is still on a changed line, it gets an inline comment.
  - If it's no longer on a changed line, it's listed in the summary comment with the commit SHA.
  - Either way, the merge is blocked. The message says to **rotate the secret**, because deleting it from the code doesn't remove it from history.
- **History in full-scan mode [my call].** Full scan checks the current tree by default. A flag (`--history`) also scans all git history.

### 6.2 Non-English comments and strings (advisory) **[user: comments and string literals; approach is my call]**
1. **Extract** comments and string literals from changed lines with a multi-language lexer. Pygments is offline and covers hundreds of languages. For files it can't lex, fall back to treating the whole line as text.
2. **Flag non-Latin script.** Any letter from a non-Latin script is flagged (CJK, Cyrillic, Arabic, Thai, Devanagari, etc.). This is certain and cheap.
3. **Check Latin-script text for language.** Latin-script text above a minimum length (for example 4 or more words) goes through an offline language identifier bundled in the image, such as `lingua`. Non-English results are flagged. This catches things like Spanish or German comments.
4. **Not flagged by default:**
   - emoji and symbols
   - URLs, file paths, format strings and placeholders
   - very short strings
   - strings that are clearly identifiers or keys
   - test fixture and i18n/locale resource files (configurable excludes)

### 6.3 Security issues (advisory, model-driven) **[my call]**
- **Input:** for each changed hunk, the model gets the diff plus surrounding context from the file.
- **Output:** a strict JSON list of findings, each with:
  - `file`, `line`
  - `severity` (high/medium/low)
  - `category` (e.g. injection, path traversal, insecure crypto, auth bypass, unsafe deserialization, SSRF, XSS)
  - `explanation`
  - `suggestion`
- **Validation:** findings must be valid JSON and must land on a changed line. Anything else is discarded, which cuts down hallucinated or off-diff findings.
- **Threshold:** a configurable minimum severity for posting. The default is medium, to keep noise down.
- **When the model is unreachable or times out,** the security check is skipped. The summary comment says so clearly, and the job does **not** fail on that. Secrets and non-English checks still run.

## 7. Behaviour details

### MR comments **[my call]**
- **One inline comment per finding,** on the changed line. Each comment carries a hidden fingerprint so it isn't re-posted on later pushes.
- **Auto-resolve.** When a finding disappears after a push, the agent resolves its own thread. It never touches human threads.
- **One summary comment per MR, edited in place:**
  - counts by check and severity
  - whether the merge is blocked and why
  - whether any check was skipped
- **Large MRs:**
  - Skip binary, generated, vendored and lock files.
  - Respect the request/token caps from §5.
  - When a cap is hit, the summary says which files weren't reviewed by the model.

### Full-scan mode **[my call; the user didn't specify where results go]**
- **Trigger:**
  - GitLab: a manual or scheduled pipeline job
  - Azure DevOps: a manually run pipeline
- **Coverage:** all three checks across all tracked files, subject to the same excludes and caps. Model caps are higher by default and configurable.
- **No inline comments.** Output is a pipeline artifact:
  - an HTML report a person can read, grouped by check, severity and file
  - JSON for machines
  - optionally SARIF, for other tooling
- **Exit code** is configurable. By default it fails if secrets are found.

### Repo config file **[my call]**
An optional `.pr-agent.yml` at the repo root controls:
- which checks are enabled
- path include/exclude globs
- the security severity threshold
- the secrets allowlist
- the minimum length for non-English text
- model caps

Org-wide defaults live in the image. The repo file overrides them.

## 8. Left to the builder

- Code structure, module layout and the platform-adapter interface (GitLab and Azure DevOps behind one interface)
- Prompt wording, chunking strategy, retries and backoff
- The exact choice between gitleaks and detect-secrets, and rule tuning
- HTML report styling
- Test strategy, including recorded fixtures for both platform APIs and a fake OpenAI-compatible server for model calls
- Build order. Suggested: GitLab MR mode with secrets, then non-English, then security, then full scan, then Azure DevOps.
