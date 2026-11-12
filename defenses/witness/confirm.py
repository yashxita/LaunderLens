"""
confirm.py  —  S6 of WITNESS: closed-choice confirmation.

Plain-English idea
------------------
When the delegated document holds several candidates for one slot and no
trusted evidence picks one, the only sound move left is to ask the principal
(design doc §3, Observation 1). The ASPI paper (arXiv 2605.17324) showed that
OPEN-ENDED clarification makes injection much worse, because the reply channel
becomes an instruction channel. So the question here is:

  * rendered by the defence, not written by the agent;
  * lists EVERY candidate with where it appears, so the user sees the competing
    value (unlike CaMeL-style or call-approval confirmation);
  * answered with an index (or "cancel"), never with free text.

Two modes for evaluation:
  abstain   no human available: the call is refused (worst case for utility)
  oracle    a simulated user picks the value the clean run used. This is the
            honest model of a real user who knows who they meant to pay; it adds
            no injection channel because the answer is only an index.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .recognisers import Candidate, map_proposal

ABSTAIN, ORACLE = "abstain", "oracle"


def render_question(tool: str, arg: str, cands: list[Candidate], texts: dict[int, str]) -> str:
    lines = [f"Before I call {tool}: the source lists {len(cands)} possible values for '{arg}'."]
    for i, c in enumerate(cands):
        ctx = ""
        t = texts.get(c.obs_index, "")
        if t:
            s, e = c.span
            ctx = t[max(0, s - 40):min(len(t), e + 40)].replace("\n", " ").strip()
        lines.append(f"  [{i + 1}] {c.raw}   (from {c.source_tool}: \"...{ctx}...\")")
    lines.append("  [0] cancel")
    lines.append("Reply with a number only.")
    return "\n".join(lines)


@dataclass
class ConfirmationPolicy:
    mode: str = ABSTAIN
    # (tool, arg) -> values the simulated user would accept (from the clean run)
    oracle_values: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    questions_asked: int = 0
    transcript: list[str] = field(default_factory=list)

    def ask(self, tool: str, arg: str, vtype: str, cands: list[Candidate],
            texts: dict[int, str]) -> Optional[int]:
        """Return the index the user picked, or None (abstain / cancel)."""
        self.transcript.append(render_question(tool, arg, cands, texts))
        if self.mode != ORACLE:
            return None
        self.questions_asked += 1
        for want in self.oracle_values.get((tool, arg), []):
            hits = map_proposal(want, vtype, cands)
            if len(hits) == 1:
                return cands.index(hits[0])
        return None  # the user recognises none of them -> cancel
