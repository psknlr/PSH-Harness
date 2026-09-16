"""One tokeniser for every place psh compares text.

Four modules were each doing their own ``re.findall(r"[a-z]...")``, and every one of them
was silently blind to Chinese:

* ``context.compiler._fingerprint`` — three distinct Chinese memories all fingerprinted to
  the empty string and deduplicated to one. Reproduced: ``candidates=3 → included=1``. A
  dedup key that is constant is not a dedup key; it is data loss with a benchmark number
  attached.
* ``capabilities.registry._terms`` — a Chinese query produced an empty term set, so
  capability ranking collapsed to a cost/latency sort with no semantic component.
* ``evidence.support._tokens`` — a Chinese claim quoted verbatim from a Chinese source
  scored 0% overlap and returned UNKNOWN. Together with the output gate's (correct)
  detection of Chinese clinical assertions, that made every Chinese clinical sentence
  permanently unreleasable: the gate demanded support the verifier could never find.

Chinese has no spaces, so the usual "split on non-letters" produces nothing. The standard
answer that needs no dictionary, no model and no dependency is **character bigrams**: they
are what CJK search engines index, they are position-sensitive enough to tell 射血分数 from
分数射血, and they degrade gracefully on mixed text. Latin words, numbers and units keep
their existing treatment, because numbers are load-bearing in this domain — "cohort 1" and
"cohort 2" must not fingerprint alike, which an earlier fix here already established.

This module is deliberately dependency-free and not a linguistic analyser. It is the
minimum that makes Chinese text *visible* to machinery that already works in English.
"""

from __future__ import annotations

import re

__all__ = ["segment", "terms", "fingerprint", "has_cjk", "CJK_RANGES"]

#: The CJK blocks psh expects in clinical and research text: unified ideographs, the
#: extension A block, and compatibility ideographs. Kana and Hangul are out of scope —
#: they would need their own segmentation, and claiming coverage we do not have is the
#: failure mode this module exists to correct.
CJK_RANGES = "一-鿿㐀-䶿豈-﫿"

_CJK_RUN = re.compile(f"[{CJK_RANGES}]+")
_LATIN_WORD = re.compile(r"[a-z][a-z0-9-]{1,}")
#: Numbers with an optional unit or percent sign, kept as one token so "0.91" and "91%"
#: are distinguishable and neither is discarded.
_NUMBER = re.compile(r"\d+(?:\.\d+)?%?")


def has_cjk(text: str) -> bool:
    return bool(_CJK_RUN.search(text))


def _bigrams(run: str) -> list[str]:
    """Character bigrams, plus the run itself when it is short enough to be one term.

    A two-character run yields one bigram; a single character yields itself, so a term like
    癌 is not lost. Runs of three or four characters also contribute the whole run, which
    is what makes 射血分数 match 射血分数 exactly rather than only through its bigrams.
    """
    if len(run) == 1:
        return [run]
    out = [run[i:i + 2] for i in range(len(run) - 1)]
    if 2 < len(run) <= 4:
        out.append(run)
    return out


def segment(text: str) -> list[str]:
    """Tokenise mixed Chinese/Latin text. Order-preserving, duplicates kept."""
    lowered = text.lower()
    out: list[str] = []
    for match in re.finditer(
            f"[{CJK_RANGES}]+|[a-z][a-z0-9-]+|\\d+(?:\\.\\d+)?%?", lowered):
        token = match.group(0)
        if _CJK_RUN.fullmatch(token):
            out.extend(_bigrams(token))
        else:
            out.append(token)
    return out


def terms(text: str, *, stopwords: frozenset[str] | set[str] = frozenset()) -> set[str]:
    """The set of retrieval terms in ``text``, minus any stopwords supplied."""
    return {t for t in segment(text) if t not in stopwords}


def fingerprint(text: str, *, limit: int = 400) -> str:
    """A normalised, order-insensitive key for deduplication.

    Case, whitespace and punctuation insensitive; numbers included, because "cohort 1
    result" and "cohort 2 result" are different items. Two texts share a fingerprint only
    if they use the same tokens — which for Chinese now means the same characters in the
    same adjacency, rather than (as before) being Chinese at all.
    """
    return " ".join(sorted(set(segment(text))))[:limit]
