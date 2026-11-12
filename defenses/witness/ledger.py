"""
ledger.py  —  the counterparty pinning ledger (S5).

Plain-English idea
------------------
Banks fight invoice-redirection fraud with "Confirmation of Payee": once you
have paid someone, a request to pay them at NEW bank details always needs an
out-of-band check. The ledger is that idea for agents.

  * A binding (vtype, value, principal) is written ONLY when the user picks a
    value in a closed-choice confirmation (S6), or by an explicit seed. Nothing
    an agent reads can write to it, so an attacker cannot plant a witness.
  * Later, a candidate that matches a pinned value is CORROBORATED, which lets
    WITNESS resolve a conflict without asking again (trust on first use).

The ledger can be kept per-run (default for evaluation, so no trace learns from
another) or persisted to a JSON file to measure the trust-on-first-use benefit.
"""

from __future__ import annotations

import json
import os
from typing import Iterator, Optional


class CounterpartyLedger:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._pins: dict[tuple[str, str], str] = {}   # (vtype, value) -> principal
        if path and os.path.exists(path):
            with open(path) as f:
                for row in json.load(f):
                    self._pins[(row["vtype"], row["value"])] = row.get("principal", "")

    def pin(self, vtype: str, value: str, principal: str = "", source: str = "user_confirmation"):
        if source != "user_confirmation" and source != "seed":
            raise ValueError("ledger pins may only come from the user or an explicit seed")
        self._pins[(vtype, value)] = principal or source
        self._save()

    def is_pinned(self, vtype: str, value: str) -> bool:
        return (vtype, value) in self._pins

    def entries(self) -> Iterator[tuple[str, str, str]]:
        for (vt, v), p in self._pins.items():
            yield vt, v, p

    def __len__(self):
        return len(self._pins)

    def _save(self):
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump([{"vtype": vt, "value": v, "principal": p} for vt, v, p in self.entries()], f, indent=1)
