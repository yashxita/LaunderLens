"""
state.py  —  trusted evidence for S4 (elimination) and S5 (corroboration).

Plain-English idea
------------------
WITNESS may only use evidence the attacker cannot write to decide between
competing candidates (design doc §3, Observation 1). This module collects that
evidence from four places:

  1. the user's prompt           values the user typed
  2. high-integrity tool reads   e.g. banking get_iban -> the user's OWN IBAN
  3. structured records          banking transactions: we parse the YAML and
                                 read only the bank-written `sender`/`recipient`
                                 fields of OUTGOING transactions (sender == "me"
                                 or the user's IBAN). The free-text `subject`
                                 field is attacker-reachable and is never read.
  4. an optional seed + the counterparty pinning ledger (ledger.py)

Everything here is deterministic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .policy import SuitePolicy
from .recognisers import ENUMERABLE_TYPES, IBAN, canonical, find_candidates

try:
    import yaml  # AgentDojo already depends on PyYAML
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class Observation:
    """One tool result, in the order the agent saw it."""
    index: int
    tool: str
    args: dict
    text: str


@dataclass
class TrustedState:
    self_values: dict[str, set[str]] = field(default_factory=dict)   # vtype -> the user's own values
    witnesses: dict[str, dict[str, str]] = field(default_factory=dict)  # vtype -> {value: provenance}
    prompt_values: dict[str, set[str]] = field(default_factory=dict)  # vtype -> values typed by user

    def add_self(self, vtype: str, value: str):
        self.self_values.setdefault(vtype, set()).add(value)

    def add_witness(self, vtype: str, value: str, provenance: str):
        self.witnesses.setdefault(vtype, {}).setdefault(value, provenance)

    def is_self(self, vtype: str, value: str) -> bool:
        return value in self.self_values.get(vtype, set())

    def witness_of(self, vtype: str, value: str) -> Optional[str]:
        return self.witnesses.get(vtype, {}).get(value)


def _outgoing_recipients(text: str, own_ibans: set[str]) -> list[str]:
    """Recipients of transactions the USER sent, read from structured fields only."""
    if yaml is None:
        return []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []  # unparseable -> no witnesses (fail safe: fewer endorsements)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    out = []
    for row in data:
        if not isinstance(row, dict):
            continue
        sender = canonical(row.get("sender", ""), IBAN)
        if sender == "ME" or sender in own_ibans:
            rec = canonical(row.get("recipient", ""), IBAN)
            if rec and rec != "ME":
                out.append(rec)
    return out


def build_trusted_state(policy: SuitePolicy, user_prompt: str, observations: list[Observation],
                        seed: Optional[dict] = None, ledger=None) -> TrustedState:
    st = TrustedState()

    # 1. user prompt
    for vt in ENUMERABLE_TYPES:
        vals = {c.value for c in find_candidates(user_prompt or "", vt)}
        if vals:
            st.prompt_values[vt] = vals
            for v in vals:
                st.add_witness(vt, v, "user_prompt")

    # 2. high-integrity reads: the user's own values
    for ob in observations:
        vt = policy.self_value_tools.get(ob.tool)
        if vt:
            for c in find_candidates(ob.text, vt):
                st.add_self(vt, c.value)

    # other enumerable values returned by trusted tools are witnesses
    for ob in observations:
        if ob.tool in policy.trusted_tools and ob.tool not in policy.self_value_tools:
            for vt in ENUMERABLE_TYPES:
                for c in find_candidates(ob.text, vt):
                    st.add_witness(vt, c.value, f"trusted_tool:{ob.tool}")

    # 3. structured records (outgoing transactions)
    own = st.self_values.get(IBAN, set())
    for ob in observations:
        if ob.tool in policy.record_tools:
            for rec in _outgoing_recipients(ob.text, own):
                st.add_witness(IBAN, rec, f"record:{ob.tool}")

    # 4a. seed exported from the benchmark environment (seed_trusted_state.py)
    if seed:
        for vt, vals in (seed.get("self") or {}).items():
            for v in vals:
                st.add_self(vt, canonical(v, vt))
        for vt, vals in (seed.get("witnesses") or {}).items():
            for v in vals:
                st.add_witness(vt, canonical(v, vt), "seed")

    # 4b. pinned counterparties
    if ledger is not None:
        for vt, v, principal in ledger.entries():
            st.add_witness(vt, v, f"pinned:{principal}")

    return st


def load_seed(path: Optional[str], suite: str) -> Optional[dict]:
    if not path:
        return None
    with open(path) as f:
        data = json.load(f)
    return data.get(suite)
