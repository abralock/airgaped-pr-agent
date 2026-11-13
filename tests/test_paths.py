import pytest

from airgap_pr_agent.config import load_config
from airgap_pr_agent.paths import PathFilter


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
