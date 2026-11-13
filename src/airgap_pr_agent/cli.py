from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .checks.secrets import SecretScanError
from .config import ConfigError, load_config
from .gitops import DiffRefs, GitError
from .llm import LLMClient
from .platforms.base import LogOnlyPlatform, Platform
from .platforms.gitlab import GitLabPlatform, refs_from_env
from .review import run_review


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pr-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    review = sub.add_parser("review", help="review a merge/pull request")
    review.add_argument("--repo", default=".")
    review.add_argument("--platform", choices=["auto", "gitlab", "azure", "local"], default="auto")
    review.add_argument("--base")
    review.add_argument("--head")
    return parser


def _platform(args: argparse.Namespace) -> Platform:
    if args.platform == "local":
        if not args.base:
            raise ConfigError("--base is required with --platform local")
        return LogOnlyPlatform(DiffRefs(args.base, args.head or "HEAD"))
    platform = args.platform
    if platform == "auto":
        if os.environ.get("GITLAB_CI") == "true":
            platform = "gitlab"
        elif os.environ.get("TF_BUILD") == "True":
            raise ConfigError("platform 'azure' is not available yet")
        else:
            raise ConfigError("cannot detect CI platform; pass --platform (or local)")
    if platform == "gitlab":
        gl = GitLabPlatform.from_env(os.environ)
        if gl is not None:
            return gl
        print(
            "pr-agent: warning: PR_AGENT_GITLAB_TOKEN is not set; "
            "findings will be printed, not posted to the merge request",
            file=sys.stderr,
        )
        return LogOnlyPlatform(refs_from_env(os.environ))
    raise ConfigError(f"platform {platform!r} is not available yet")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        repo = Path(args.repo)
        cfg = load_config(repo)
        llm = LLMClient.from_env(cfg.llm, os.environ, max_requests=cfg.llm.max_requests_per_mr)
        platform = _platform(args)
        gitleaks_bin = os.environ.get("GITLEAKS_BIN", "gitleaks")
        return run_review(repo, platform, cfg, llm, gitleaks_bin)
    except (SecretScanError, ConfigError, GitError) as exc:
        print(f"pr-agent: error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - CI must see a clear, distinct exit code
        print(f"pr-agent: error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
