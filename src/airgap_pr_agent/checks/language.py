"""Detect non-English text in comments and string literals of changed lines."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from typing import Literal

from lingua import Language, LanguageDetectorBuilder
from pygments.lexers import get_lexer_for_filename
from pygments.lexers.special import TextLexer
from pygments.token import Token
from pygments.util import ClassNotFound

from ..config import NonEnglishConfig
from ..gitops import ChangedFile
from ..models import Check, CheckResult, Finding, Severity, fingerprint
from ..paths import PathFilter

Kind = Literal["comment", "string", "line"]


@dataclass
class TextSpan:
    start: int  # 1-based first line
    end: int  # 1-based last line
    kind: Kind
    text: str


def _token_kind(ttype) -> Kind | None:
    if ttype in Token.Comment:
        return "comment"
    if ttype in Token.Literal.String.Doc:
        return "comment"
    if ttype in Token.Literal.String:
        return "string"
    return None


def _line_spans(source: str) -> list[TextSpan]:
    return [TextSpan(i, i, "line", t) for i, t in enumerate(source.splitlines(), 1) if t.strip()]


def extract_spans(path: str, source: str) -> list[TextSpan]:
    try:
        lexer = get_lexer_for_filename(path, source)
    except ClassNotFound:
        return _line_spans(source)
    if isinstance(lexer, TextLexer):
        return _line_spans(source)

    spans: list[TextSpan] = []
    line = 1
    cur: tuple[Kind, int, list[str]] | None = None  # kind, start line, text parts

    def flush() -> None:
        nonlocal cur
        if cur is not None:
            kind, start, parts = cur
            text = "".join(parts)
            body = text.rstrip("\n")
            if body.strip():
                spans.append(TextSpan(start, start + body.count("\n"), kind, body))
            cur = None

    for ttype, value in lexer.get_tokens(source):
        kind = _token_kind(ttype)
        if kind is None:
            flush()
        elif cur is not None and cur[0] == kind:
            cur[2].append(value)
        else:
            flush()
            cur = (kind, line, [value])
        line += value.count("\n")
    flush()
    return spans


_URL = re.compile(r"https?://\S+")
_PATH = re.compile(r"(?:[\w.~-]*/)+[\w.-]*")
_PRINTF = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[a-zA-Z%]|%\([^)]*\)[a-zA-Z]")
_BRACES = re.compile(r"\$?\{[^{}]*\}")
_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", re.S)
_GREEK_WORD = re.compile(r"[\u0370-\u03ff\u1f00-\u1fff]{4,}")
_WORD = re.compile(r"[^\W\d_]+")


def _clean(text: str) -> str:
    for rx in (_URL, _PATH, _PRINTF, _BRACES, _ESCAPE):
        text = rx.sub(" ", text)
    return text


@cache
def _detector():
    # Fixed Latin-free-of-"Latin" candidate set: the generic Latin model
    # misclassifies short technical English, so it is excluded.
    L = Language
    return LanguageDetectorBuilder.from_languages(
        L.ENGLISH, L.SPANISH, L.FRENCH, L.GERMAN, L.PORTUGUESE, L.ITALIAN, L.DUTCH,
        L.INDONESIAN, L.MALAY, L.VIETNAMESE, L.TURKISH, L.POLISH, L.TAGALOG,
        L.SWEDISH, L.ROMANIAN, L.CZECH,
    ).build()


def _script(ch: str) -> str:
    word = unicodedata.name(ch, "").split(" ", 1)[0].title()
    return "Chinese/Japanese" if word == "Cjk" else word


def classify(text: str, min_words: int, min_confidence: float, latin_check: bool = True) -> str | None:
    text = _clean(text)
    if _GREEK_WORD.search(text):
        return "non-Latin script (Greek)"
    for ch in text:
        if ch == "\u00b5":  # MICRO SIGN (units such as µs) is always allowed
            continue
        if ch.isalpha() and not unicodedata.name(ch, "").startswith("LATIN"):
            script = _script(ch)
            if script == "Greek":  # isolated Greek letters are math/units notation
                continue
            return f"non-Latin script ({script})"
    if not latin_check or len(_WORD.findall(text)) < min_words:
        return None
    values = _detector().compute_language_confidence_values(text)
    if not values:
        return None
    top = values[0]
    if top.language != Language.ENGLISH and top.value >= min_confidence:
        return f"{top.language.name.title()} text"
    return None


def _norm(text: str) -> str:
    return " ".join(text.split()).lower()


def non_english_findings(
    files: list[ChangedFile], cfg: NonEnglishConfig, path_filter: PathFilter
) -> CheckResult:
    findings: list[Finding] = []
    for f in files:
        if not path_filter.allows(f.path):
            continue
        for span in extract_spans(f.path, f.source):
            line = next((n for n in range(span.start, span.end + 1) if n in f.added), None)
            if line is None:
                continue
            reason = classify(
                span.text, cfg.min_words, cfg.min_confidence, latin_check=span.kind != "line"
            )
            if reason is None:
                continue
            title = {
                "comment": "Non-English text in comment",
                "string": "Non-English text in string",
                "line": "Non-English text",
            }[span.kind]
            quoted = " ".join(span.text.split())[:80]
            findings.append(
                Finding(
                    check=Check.NON_ENGLISH,
                    path=f.path,
                    line=line,
                    severity=Severity.LOW,
                    title=title,
                    message=f'"{quoted}" ({reason})',
                    fingerprint=fingerprint("non_english", f.path, span.kind, _norm(span.text)),
                    rule="non-english",
                )
            )
    return CheckResult(Check.NON_ENGLISH, findings)
