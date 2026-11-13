# syntax=docker/dockerfile:1
#
# Offline pr-agent image. Everything the agent needs at runtime (Python deps,
# gitleaks, git) is baked in; nothing is fetched when it runs.
#
#   scripts/fetch-gitleaks.sh            # or copy the tarballs into vendor/
#   docker build --target test .         # full test suite, gitleaks required
#   docker build -t pr-agent:dev .
#
# Build-time network: Python packages come from PyPI or PIP_INDEX_URL (an
# internal mirror) and are hash-verified; git comes from the base image's apt
# sources.

# python:3.12-slim, multi-arch index digest.
ARG BASE_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG GITLEAKS_VERSION=8.30.1

FROM ${BASE_IMAGE} AS base
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 agent \
 && git config --system --add safe.directory '*'

# gitleaks, verified against the committed checksum for the target arch.
FROM base AS gitleaks
ARG GITLEAKS_VERSION
ARG TARGETARCH
COPY vendor/gitleaks-${GITLEAKS_VERSION}.sha256 vendor/gitleaks_${GITLEAKS_VERSION}_linux_*.tar.gz /tmp/vendor/
WORKDIR /tmp/vendor
RUN case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) arch=x64 ;; \
      arm64) arch=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && name="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
 && grep "  ${name}\$" "gitleaks-${GITLEAKS_VERSION}.sha256" > /tmp/gitleaks.sha256 \
 && sha256sum -c /tmp/gitleaks.sha256 \
 && tar -xzf "$name" -C /usr/local/bin gitleaks \
 && chmod 0755 /usr/local/bin/gitleaks \
 && /usr/local/bin/gitleaks version

# The project wheel, built with a hash-locked setuptools.
FROM base AS wheel
ARG PIP_INDEX_URL
WORKDIR /src
COPY requirements-build.lock ./
RUN [ -n "${PIP_INDEX_URL:-}" ] && export PIP_INDEX_URL || unset PIP_INDEX_URL; \
    python -m venv /opt/build \
 && /opt/build/bin/pip install --require-hashes -r requirements-build.lock
COPY pyproject.toml ./
COPY src ./src
RUN /opt/build/bin/pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

# Runtime virtualenv: hash-locked dependencies plus the project wheel.
FROM base AS deps
ARG PIP_INDEX_URL
COPY requirements.lock /tmp/requirements.lock
RUN [ -n "${PIP_INDEX_URL:-}" ] && export PIP_INDEX_URL || unset PIP_INDEX_URL; \
    python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r /tmp/requirements.lock
COPY --from=wheel /wheels /tmp/wheels
RUN /opt/venv/bin/pip install --no-index --no-deps /tmp/wheels/*.whl
COPY --from=gitleaks /usr/local/bin/gitleaks /usr/local/bin/gitleaks
ENV PATH=/opt/venv/bin:$PATH \
    GITLEAKS_BIN=/usr/local/bin/gitleaks

# Full test suite against the installed wheel. gitleaks is mandatory here:
# a missing binary fails the tests, and any skipped test fails the stage.
FROM deps AS test
ARG PIP_INDEX_URL
COPY requirements-dev.lock /tmp/requirements-dev.lock
RUN [ -n "${PIP_INDEX_URL:-}" ] && export PIP_INDEX_URL || unset PIP_INDEX_URL; \
    /opt/venv/bin/pip install --require-hashes -r /tmp/requirements-dev.lock
WORKDIR /home/agent/src
COPY --chown=agent pyproject.toml ./
COPY --chown=agent tests ./tests
COPY --chown=agent templates ./templates
COPY --chown=agent .github/workflows ./.github/workflows
USER agent
RUN PR_AGENT_REQUIRE_GITLEAKS=1 python -m pytest -q -rs -p no:cacheprovider 2>&1 | tee /tmp/pytest.log \
 && if grep -Eq '[0-9]+ skipped' /tmp/pytest.log; then echo "error: tests were skipped" >&2; exit 1; fi

FROM base AS final
COPY --from=deps /opt/venv /opt/venv
COPY --from=gitleaks /usr/local/bin/gitleaks /usr/local/bin/gitleaks
ENV PATH=/opt/venv/bin:$PATH \
    GITLEAKS_BIN=/usr/local/bin/gitleaks
USER 10001
WORKDIR /home/agent
CMD ["pr-agent", "--help"]
