"""
arch_b_hybrid.py  —  Direction B: provenance-routed hybrid.

Best-of-breed composition. Each sink argument is ROUTED to the single component
that is sound for its provenance class, instead of STACKING every defence
(stacking multiplies false positives and kills utility). The delegated-value lane
has no sound prior component, so it uses the WITNESS core from Direction A.
See design/DEFENSE_DESIGN.md §4.

Run from the repo root:
    python design/arch_b_hybrid.py
Output: diagrams/arch_b_hybrid.png + .pdf
"""

from _draw import canvas, box, tag, arrow, line, legend, save, OI


def draw():
    fig, ax = canvas(13.0, 12.6,
                     "Direction B — Provenance-routed hybrid (best-of-breed + WITNESS core)",
                     xlim=(0, 16.0), ylim=(0.3, 14.6))

    # ── row 1: inputs, context isolator, agent ─────────────────────────────
    box(ax, 1.9, 13.6, 3.4, 1.2, "User prompt", "trusted", role="trusted")
    box(ax, 6.4, 13.6, 4.0, 1.2, "Agent LLM", "proposes sink call f(args)", role="agent")
    box(ax, 10.7, 13.6, 3.6, 1.35, "Context isolator",
        "DRIFT-style: mask spans that\nconflict with the prompt", role="adopted")
    box(ax, 14.4, 13.6, 2.8, 1.2, "Tool outputs", "untrusted", role="untrusted")
    arrow(ax, 3.6, 13.6, 4.4, 13.6)
    arrow(ax, 13.0, 13.6, 12.5, 13.6)
    arrow(ax, 8.9, 13.6, 8.4, 13.6)

    # ── row 2: router, fence, optional counterfactual ──────────────────────
    box(ax, 1.9, 11.2, 3.4, 1.75, "Provenance Router",
        "prompt only (ROPE +\nAuthGraph planner):\nper sink arg -> lane 1..5", role="adopted")
    box(ax, 6.4, 11.2, 4.0, 1.75, "Control Fence",
        "IPIGuard / AuthGraph plan graph\nundeclared tool or slot -> BLOCK", role="adopted")
    box(ax, 11.6, 11.2, 4.4, 1.75, "Counterfactual check (optional)",
        "action-open tasks only\n(\"do the to-do list in this file\")\nAttriGuard / AgentSentry replay, ~2x",
        role="llm", dashed=True)
    arrow(ax, 1.9, 13.0, 1.9, 12.08)
    arrow(ax, 6.4, 13.0, 6.4, 12.08, label="sink call")
    arrow(ax, 3.6, 11.2, 4.4, 11.2, label="routes", lbl_off=(0, 0.17), lbl_ha="center")
    arrow(ax, 8.4, 11.2, 9.4, 11.2, dashed=True, color=OI["purple"])

    # ── fan-out bus to the five lanes ──────────────────────────────────────
    xs = [1.9, 5.0, 8.1, 11.2, 14.3]
    y_bus = 9.75
    line(ax, [6.4, 6.4], [10.32, y_bus])
    line(ax, [xs[0], xs[-1]], [y_bus, y_bus])
    for x in xs:
        arrow(ax, x, y_bus, x, 9.25)

    lw, lh, ly = 2.95, 2.3, 8.05
    box(ax, xs[0], ly, lw, lh, "1  User literal",
        "value typed by user\n\ndeterministic match\n(ROPE prompt marker)", role="adopted")
    box(ax, xs[1], ly, lw, lh, "2  Trusted record",
        "value from own records\n\ndeterministic match\n(ROPE record marker)", role="adopted")
    box(ax, xs[2], ly, lw, lh, "3  Delegated value",
        "value read from a doc\n\nWITNESS core: enumerate,\neliminate, pin, confirm", role="novel")
    box(ax, xs[3], ly, lw, lh, "4  Derived value",
        "\"the cheapest hotel\"\n\ntyped Q-LLM, enum-bound\n(FIDES / CaMeL) + fact\nsupport (AuthorityFlow)",
        role="adopted")
    box(ax, xs[4], ly, lw, lh, "5  Free text",
        "email body, message\n\ncapacity label (FIDES)\n+ sanitiser (CausalArmor);\nno high-impact sink",
        role="adopted")

    # ── merge bus to the decision ──────────────────────────────────────────
    y_m = 6.35
    for x in xs:
        line(ax, [x, x], [ly - lh / 2, y_m])
    line(ax, [xs[0], xs[-1]], [y_m, y_m])
    arrow(ax, 8.1, y_m, 8.1, 5.75, label="per-argument verdicts")

    box(ax, 8.1, 5.15, 6.4, 1.2, "Call decision",
        "all ALLOW -> run    any BLOCK -> block    otherwise ESCALATE",
        role="agent")
    box(ax, 13.9, 5.15, 3.6, 1.2, "LLM veto (shared)",
        "may only downgrade", role="llm", dashed=True)
    arrow(ax, 12.1, 5.15, 11.3, 5.15, dashed=True, color=OI["purple"])

    # outcomes
    oxs = [4.0, 8.1, 12.2]
    y_o = 3.95
    line(ax, [8.1, 8.1], [4.55, y_o])
    line(ax, [oxs[0], oxs[-1]], [y_o, y_o])
    for x in oxs:
        arrow(ax, x, y_o, x, 3.55)
    tag(ax, oxs[0], 3.2, "ALLOW", "executes with\ncanonical values")
    tag(ax, oxs[1], 3.2, "ESCALATE", "closed-choice\nconfirm / ABSTAIN")
    tag(ax, oxs[2], 3.2, "BLOCK", "denial returned\nto agent (replan)")

    box(ax, 8.1, 1.45, 15.2, 1.15, "Per-argument label log  ->  two-sided LIS audit",
        "same label schema as Direction A, plus the lane each argument was routed to",
        role="audit")
    arrow(ax, 8.1, 2.88, 8.1, 2.03)

    legend(ax, [("trusted", "trusted input"), ("untrusted", "untrusted input"),
                ("novel", "novel (ours)"), ("adopted", "adopted from prior work"),
                ("llm", "LLM, optional / veto-only")], ncol=5)
    save(fig, "arch_b_hybrid")


if __name__ == "__main__":
    draw()
