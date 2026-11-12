"""
seed_trusted_state.py  —  export WITNESS's trusted evidence from AgentDojo's environments.

Plain-English idea
------------------
In a real deployment WITNESS would read the user's own records (own IBAN, people
they have paid before) directly from the bank, not from whatever the agent
happened to read. This script exports exactly those high-integrity values from
each AgentDojo suite's default environment into one JSON file, which
run_witness_replay.py / run_phase4.py can load with --trusted-seed.

Only structured fields written by the "bank"/directory are exported:
  banking   own IBAN; recipients of OUTGOING transactions and scheduled
            transactions (sender == own IBAN or "me")
  slack     (nothing enumerable yet: users have no e-mail in the environment)

Needs AgentDojo installed (run on the machine that runs the benchmark).

    python experiments/seed_trusted_state.py                       # -> experiments/results/trusted_seed.json
    python experiments/seed_trusted_state.py --out some/path.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env(version: str, suite_name: str):
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(version, suite_name)
    defaults = suite.get_injection_vector_defaults()
    return suite.load_and_inject_default_environment(defaults)


def banking_seed(env) -> dict:
    acct = env.bank_account
    own = str(acct.iban)
    witnesses = set()
    for txn in list(getattr(acct, "transactions", [])) + list(getattr(acct, "scheduled_transactions", [])):
        sender = str(getattr(txn, "sender", ""))
        if sender in (own, "me"):
            rec = str(getattr(txn, "recipient", ""))
            if rec and rec != "me":
                witnesses.add(rec)
    return {"self": {"iban": [own]}, "witnesses": {"iban": sorted(witnesses)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--out", default=os.path.join(_ROOT, "experiments", "results", "trusted_seed.json"))
    args = ap.parse_args()

    seed = {}
    try:
        seed["banking"] = banking_seed(_load_env(args.version, "banking"))
    except Exception as e:
        print(f"[!] banking export failed: {e}")
        print("    Check `pip show agentdojo` and try --version v1.2")
        sys.exit(1)
    seed["slack"] = {"self": {}, "witnesses": {}}

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(seed, f, indent=2)
    print(f"wrote {args.out}")
    for s, v in seed.items():
        print(f"  {s}: self={v.get('self')}  witnesses={v.get('witnesses')}")


if __name__ == "__main__":
    main()
