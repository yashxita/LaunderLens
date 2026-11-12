"""
arch_a_witness.py  —  Direction A: WITNESS (the novel defence).

Nonmalleable endorsement of delegated values: a value taken from an untrusted
document reaches a sink only if the decision to endorse it cannot be steered by
attacker-appended text. See design/DEFENSE_DESIGN.md §3.

Run from the repo root:
    python design/arch_a_witness.py
Output: diagrams/arch_a_witness.png + .pdf
"""

from _draw import canvas, box, tag, arrow, line, legend, save, OI


def draw():
    fig, ax = canvas(11.5, 13.2,
                     "Direction A — WITNESS: nonmalleable endorsement of delegated values",
                     xlim=(0, 14.4), ylim=(0.3, 16.7))

    # ── row 1: inputs + agent ──────────────────────────────────────────────
    box(ax, 2.6, 15.8, 4.2, 1.2, "User prompt  (trusted)",
        '"Pay the bill in bill.txt"', role="trusted")
    box(ax, 7.6, 15.8, 4.6, 1.2, "Agent LLM  (unchanged)",
        "reads everything, proposes sink call f(args)", role="agent")
    box(ax, 12.4, 15.8, 3.6, 1.2, "Tool outputs  (untrusted)",
        "attacker may APPEND spans", role="untrusted")
    arrow(ax, 4.7, 15.8, 5.3, 15.8)
    arrow(ax, 10.6, 15.8, 9.9, 15.8)

    # ── left column: trusted / untrusted inputs to the gate ────────────────
    box(ax, 2.6, 13.3, 4.2, 1.6, "S1  Intent Slot Compiler",
        "sees ONLY prompt + tool schemas\nemits a slot spec per sink arg:\nsource, type, cardinality, impact",
        role="adopted")
    box(ax, 2.6, 10.9, 4.2, 1.3, "Delegated source D",
        "the observation the slot is\ndelegated to (e.g. bill.txt)", role="untrusted")
    box(ax, 2.6, 8.7, 4.2, 1.5, "Trusted state",
        "get_iban, own email, contacts /\nuser directory, user-initiated txns",
        role="trusted")
    box(ax, 2.6, 5.75, 4.2, 1.5, "Counterparty pinning ledger",
        "principal -> value bindings\nwritten ONLY by user choice\n(trust-on-first-use)", role="novel")
    arrow(ax, 2.6, 15.2, 2.6, 14.1)
    arrow(ax, 2.6, 7.95, 2.6, 6.45, label="seeds")

    # ── centre column: the gate pipeline ───────────────────────────────────
    cx, w = 7.6, 4.6
    box(ax, cx, 13.3, w, 1.6, "S2  Control Fence",
        "tool and slot must be declared by S1\n(data may flow in, control may not)",
        role="adopted")
    box(ax, cx, 10.9, w, 1.6, "S3  Typed Candidate Enumerator",
        "deterministic: regex + checksum\nC = every valid value of the slot type in D\nproposal fuzzy-matched -> canonical value",
        role="novel")
    box(ax, cx, 8.7, w, 1.5, "S4  Trusted Elimination",
        "drop candidates equal to trusted 'self'\nvalues; never reads D's wording",
        role="novel")
    box(ax, cx, 7.2, 2.4, 0.7, "|C| = 1 ?", role="agent", bar_h=0.7)
    box(ax, cx, 5.75, w, 1.4, "S5  Trusted Corroboration",
        "exactly one candidate matches a\npinned or trusted counterparty?",
        role="novel")
    box(ax, cx, 3.7, w, 1.7, "S6  Closed-Choice Confirmation",
        "defence-rendered, shows ALL candidates\nanswer = index, never free text\nautonomous mode -> ABSTAIN",
        role="novel")

    arrow(ax, cx, 15.2, cx, 14.1, label="sink call")
    arrow(ax, cx, 12.5, cx, 11.7)
    arrow(ax, cx, 10.1, cx, 9.45)
    arrow(ax, cx, 7.95, cx, 7.55)
    arrow(ax, cx, 6.85, cx, 6.45, label="|C| > 1")
    arrow(ax, cx, 5.05, cx, 4.55, label="none / several")

    arrow(ax, 4.7, 13.3, 5.3, 13.3)
    arrow(ax, 4.7, 10.9, 5.3, 10.9)
    arrow(ax, 4.7, 8.7, 5.3, 8.7)
    arrow(ax, 4.7, 5.75, 5.3, 5.75)

    # user choice pins the value (feedback)
    line(ax, [5.3, 2.6], [3.7, 3.7], dashed=True, color=OI["orange"])
    arrow(ax, 2.6, 3.7, 2.6, 4.98, dashed=True, color=OI["orange"],
          label="user choice pins value")

    # ── right column: outcomes + veto ──────────────────────────────────────
    tx = 12.4
    tag(ax, tx, 13.3, "BLOCK", "undeclared tool / slot\n(control influence)")
    tag(ax, tx, 10.9, "BLOCK", "proposal not in C\n(fail-closed)")
    tag(ax, tx, 7.2, "ENDORSE", "unique candidate\n(Prop. 2: sound)")
    tag(ax, tx, 5.75, "ENDORSE", "exactly one\ncorroborated / pinned")
    tag(ax, tx, 3.7, "ESCALATE", "user picks one,\nor ABSTAIN")
    for y in (13.3, 10.9, 5.75, 3.7):
        arrow(ax, cx + w / 2, y, tx - 1.8, y)
    arrow(ax, cx + 1.2, 7.2, tx - 1.8, 7.2, label="yes", lbl_off=(0, 0.15), lbl_ha="center")

    box(ax, tx, 8.75, 3.6, 1.35, "V  LLM veto (optional)",
        "quarantined, tool-less\nmay only ENDORSE -> ESCALATE", role="llm", dashed=True)
    arrow(ax, tx - 1.8, 8.7, cx + w / 2, 8.7, dashed=True, color=OI["purple"])

    # ── bottom: label log for two-sided LIS ────────────────────────────────
    box(ax, 7.2, 1.45, 13.4, 1.2, "Per-argument label log  ->  two-sided LIS audit",
        "ENDORSED-unique | ENDORSED-corroborated | ENDORSED-confirmed | "
        "BLOCKED-control | BLOCKED-unsupported | ESCALATED | ABSTAINED",
        role="audit")
    arrow(ax, cx, 2.85, cx, 2.05)

    legend(ax, [("trusted", "trusted input"), ("untrusted", "untrusted input"),
                ("novel", "novel (ours)"), ("adopted", "adapted from prior work"),
                ("llm", "LLM, veto-only")], ncol=5)
    save(fig, "arch_a_witness")


if __name__ == "__main__":
    draw()
