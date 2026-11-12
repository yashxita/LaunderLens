"""
recognisers.py  —  S3 of WITNESS: deterministic, typed candidate recognisers.

Plain-English idea
------------------
Given a piece of text (a tool observation) and a value TYPE (iban, email, url,
amount), list EVERY value of that type that appears in the text. No LLM is
involved anywhere in this file, so there is nothing for a prompt injection to
talk to: the attacker can only influence WHICH strings are present, never how
they are read.

Design rules (see design/DEFENSE_DESIGN.md §4, S3):
  * Recognisers are deliberately small and auditable. They are part of the
    trusted computing base. A value the recogniser misses makes the gate FAIL
    CLOSED (the agent's proposal is "not in C"), so a recogniser gap costs
    utility, never security.
  * Distinct values are kept distinct (exact canonical identity). Fuzzy
    matching is used ONLY to map the agent's proposed value onto a candidate,
    never to merge two candidates (adaptive attack A6: near-duplicate IBAN).
  * No checksum is required for IBANs. AgentDojo's IBANs are not ISO-valid
    (e.g. "UK12345678901234567890"; "UK" is not an ISO country code), so a
    mod-97 check would reject every legitimate value in the benchmark. The
    optional strict mode exists for real deployments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# Value types the gate understands. "identity" types get the full
# uniqueness/corroboration pipeline; "amount" is a quantity type.
IBAN = "iban"
EMAIL = "email"
URL = "url"
AMOUNT = "amount"
ENUMERABLE_TYPES = (IBAN, EMAIL, URL, AMOUNT)


@dataclass(frozen=True)
class Candidate:
    """One value of a given type found in one observation."""
    value: str                 # canonical form (used for identity comparisons)
    raw: str                   # exactly as it appeared in the text
    vtype: str                 # IBAN / EMAIL / URL / AMOUNT
    source_tool: str = ""      # which tool produced the observation
    obs_index: int = -1        # position of that observation in the run
    span: tuple[int, int] = (0, 0)


# ---------------------------------------------------------------------------
# IBAN
# ---------------------------------------------------------------------------
# Compact form: CC + 2 check digits + 11..30 alphanumerics, e.g. UK12345678901234567890.
_IBAN_COMPACT = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}[A-Z0-9]{11,30})(?![A-Za-z0-9])")
# Printed form with single spaces every 4 chars, e.g. DE89 3704 0044 0532 0130 00.
_IBAN_SPACED = re.compile(
    r"(?<![A-Za-z0-9])([A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)(?![A-Za-z0-9])"
)


def canonical_iban(s: str) -> str:
    return re.sub(r"\s+", "", str(s)).upper()


def _plausible_iban(c: str) -> bool:
    return 15 <= len(c) <= 34 and sum(ch.isdigit() for ch in c) >= 8


def iban_checksum_ok(c: str) -> bool:
    """ISO 13616 mod-97 check. Only used in strict mode (see module docstring)."""
    c = canonical_iban(c)
    if not _plausible_iban(c):
        return False
    rearranged = c[4:] + c[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def find_ibans(text: str, strict_checksum: bool = False) -> list[tuple[str, str, tuple[int, int]]]:
    out, taken = [], []
    for rx in (_IBAN_COMPACT, _IBAN_SPACED):
        for m in rx.finditer(text or ""):
            s, e = m.span(1)
            if any(s < te and ts < e for ts, te in taken):
                continue  # overlaps a match we already have
            canon = canonical_iban(m.group(1))
            if not _plausible_iban(canon):
                continue
            if strict_checksum and not iban_checksum_ok(canon):
                continue
            taken.append((s, e))
            out.append((canon, m.group(1), (s, e)))
    return out


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")


def canonical_email(s: str) -> str:
    return str(s).strip().strip(".,;:'\"<>()[]").lower()


def find_emails(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    return [(canonical_email(m.group(1)), m.group(1), m.span(1)) for m in _EMAIL.finditer(text or "")]


# ---------------------------------------------------------------------------
# URL
# ---------------------------------------------------------------------------
# Bare hosts only count if the TLD is a common web TLD, so file names like
# "bill-december-2023.txt" or "notes.docx" are not mistaken for websites.
_WEB_TLDS = (
    "com|org|net|io|ai|co|uk|de|fr|info|gov|edu|app|dev|me|us|biz|xyz|site|"
    "online|shop|blog|eu|ca|au|in|ch|nl|se|es|it|jp"
)
_URL = re.compile(
    r"(?<![@A-Za-z0-9.\-])("
    r"(?:https?://[^\s<>\"'()\[\]]+)"                                   # explicit scheme
    r"|(?:www\.[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+(?:/[^\s<>\"'()\[\]]*)?)"  # www. host
    rf"|(?:[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.(?:{_WEB_TLDS})(?:/[^\s<>\"'()\[\]]*)?)"  # bare host
    r")(?![A-Za-z0-9@])",
    re.IGNORECASE,
)


def canonical_url(s: str) -> str:
    u = str(s).strip().strip(".,;:'\"<>()[]").lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    return u.rstrip("/")


def find_urls(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    out = []
    for m in _URL.finditer(text or ""):
        raw = m.group(1).rstrip(".,;:")
        out.append((canonical_url(raw), raw, (m.start(1), m.start(1) + len(raw))))
    return out


# ---------------------------------------------------------------------------
# Amount
# ---------------------------------------------------------------------------
# Broad on purpose: amounts are checked by MEMBERSHIP by default (is the agent's
# amount present in the delegated document?), so recall matters more than
# precision. Dates, times and digits inside IBANs/emails are excluded.
_NUMBER = re.compile(r"(?<![A-Za-z0-9.\-/:])(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)(?![A-Za-z0-9\-/:]|\.\d)")
_YEAR = re.compile(r"(?:19|20)\d{2}")
_MONEY_CONTEXT = re.compile(r"[$€£]\s*$|\b(amount|total|due|pay|send|price|cost|sum)\b[^0-9]*$", re.I)
_DATE_LIKE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|\d{1,2}:\d{2}")


def canonical_amount(v) -> Optional[str]:
    try:
        x = float(str(v).replace(",", "").replace("$", "").replace("€", "").replace("£", "").strip())
    except (TypeError, ValueError):
        return None
    return f"{x:.2f}"


def find_amounts(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    text = text or ""
    blocked: list[tuple[int, int]] = [m.span() for m in _DATE_LIKE.finditer(text)]
    blocked += [span for _, _, span in find_ibans(text)]
    blocked += [span for _, _, span in find_emails(text)]
    out = []
    for m in _NUMBER.finditer(text):
        s, e = m.span(1)
        if any(s < be and bs < e for bs, be in blocked):
            continue
        if _YEAR.fullmatch(m.group(1)) and not _MONEY_CONTEXT.search(text[max(0, s - 14):s]):
            continue  # "December 2023" is a year, not an amount
        canon = canonical_amount(m.group(1))
        if canon is not None:
            out.append((canon, m.group(1), (s, e)))
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
_FINDERS = {IBAN: find_ibans, EMAIL: find_emails, URL: find_urls, AMOUNT: find_amounts}
_CANON = {IBAN: canonical_iban, EMAIL: canonical_email, URL: canonical_url, AMOUNT: canonical_amount}


def canonical(value, vtype: str) -> Optional[str]:
    if value is None:
        return None
    fn = _CANON.get(vtype)
    return fn(value) if fn else str(value).strip()


def find_candidates(text: str, vtype: str, source_tool: str = "", obs_index: int = -1,
                    strict_checksum: bool = False) -> list[Candidate]:
    """All values of `vtype` in `text`, de-duplicated by canonical value (first span kept)."""
    if vtype == IBAN:
        found = find_ibans(text, strict_checksum=strict_checksum)
    else:
        finder = _FINDERS.get(vtype)
        if finder is None:
            return []
        found = finder(text)
    seen, out = set(), []
    for canon, raw, span in found:
        if canon in seen:
            continue
        seen.add(canon)
        out.append(Candidate(canon, raw, vtype, source_tool, obs_index, span))
    return out


def dedupe(cands: Iterable[Candidate]) -> list[Candidate]:
    seen, out = set(), []
    for c in cands:
        if c.value not in seen:
            seen.add(c.value)
            out.append(c)
    return out


def _iban_prefix_match(a: str, b: str, min_prefix: int = 15) -> bool:
    """Same rule as metrics/iban_match.py: tolerate trailing-digit garbling by the agent."""
    if len(a) < min_prefix or len(b) < min_prefix:
        return a == b
    return a[:min_prefix] == b[:min_prefix]


def map_proposal(value, vtype: str, cands: list[Candidate], fuzzy: bool = True) -> list[Candidate]:
    """
    Which candidates could the agent's proposed `value` be a copy of?

    Exact canonical matches win outright. Only if there is no exact match do we
    fall back to fuzzy matching (IBAN prefix rule, amount tolerance). A result
    with more than one candidate means the mapping itself is ambiguous; the
    gate treats that as a conflict, never as a pick.
    """
    v = canonical(value, vtype)
    if v is None or v == "":
        return []
    exact = [c for c in cands if c.value == v]
    if exact or not fuzzy:
        return exact
    if vtype == IBAN:
        return [c for c in cands if _iban_prefix_match(v, c.value)]
    if vtype == AMOUNT:
        return [c for c in cands if abs(float(c.value) - float(v)) < 0.005]
    return []


def values_in_text(text: str, vtype: str) -> set[str]:
    return {c.value for c in find_candidates(text, vtype)}
