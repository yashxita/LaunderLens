"""
architecture_diagram.py  —  LaunderLens system architecture.

Clean academic style (Okabe-Ito palette, serif fonts, white bg, 300 dpi).
Arrow discipline:
  - All inter-layer arrows are STRAIGHT VERTICAL.
  - 1-to-many fan-outs use a HORIZONTAL BUS BAR + short vertical drops.
  - No curves, no diagonals, no crossing lines.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import matplotlib.lines as mlines

ROOT   = os.path.dirname(os.path.abspath(__file__))
FIGDIR = os.path.join(ROOT, "diagrams")
os.makedirs(FIGDIR, exist_ok=True)

# ── Okabe-Ito palette ───────────────────────────────────────────────────────
OI = {
    "blue":       "#0072B2",
    "orange":     "#E69F00",
    "green":      "#009E73",
    "vermillion": "#D55E00",
    "purple":     "#CC79A7",
    "skyblue":    "#56B4E9",
}
LAYER = {
    "L1": {"face": "#EAF4FF", "edge": "#9DC8E8", "bar": OI["skyblue"]},
    "L2": {"face": "#FFF8EC", "edge": "#E8C870", "bar": OI["orange"]},
    "L3": {"face": "#FFF0E8", "edge": "#E8A890", "bar": OI["vermillion"]},
    "L4": {"face": "#E6F7F2", "edge": "#70C8A8", "bar": OI["green"]},
    "L5": {"face": "#F5F0FA", "edge": "#C8A8D8", "bar": OI["purple"]},
}


def set_style():
    plt.rcParams.update({
        "font.family":       "serif",
        "font.serif":        ["DejaVu Serif"],
        "figure.facecolor":  "white",
        "axes.facecolor":    "white",
        "savefig.facecolor": "white",
        "savefig.bbox":      "tight",
        "savefig.dpi":       300,
    })


def save(fig, stem):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(FIGDIR, f"{stem}.{ext}"))
    plt.close(fig)
    print(f"  Wrote diagrams/{stem}.png  +  .pdf")


# ── drawing helpers ─────────────────────────────────────────────────────────

def mod(ax, cx, cy, w, h, title, subtitle="", lk="L1",
        bar_h=0.28, title_fs=8.5, sub_fs=7.1):
    """Rounded module box with a coloured title bar."""
    lc = LAYER[lk]
    # shell
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle="round,pad=0.02",
        facecolor=lc["face"], edgecolor=lc["edge"],
        linewidth=1.2, zorder=3,
    ))
    # title bar
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy + h/2 - bar_h), w, bar_h,
        boxstyle="round,pad=0.01",
        facecolor=lc["bar"], edgecolor="none",
        zorder=4, clip_on=False,
    ))
    ax.text(cx, cy + h/2 - bar_h/2, title,
            ha="center", va="center",
            fontsize=title_fs, color="white",
            fontweight="bold", fontfamily="serif", zorder=5)
    if subtitle:
        ax.text(cx, cy - bar_h*0.10, subtitle,
                ha="center", va="center",
                fontsize=sub_fs, color="#333333",
                fontstyle="italic", fontfamily="serif", zorder=5)


def varrow(ax, x, y_top, y_bot, color="#666666", lw=1.1, label="", lbl_x_off=0.10):
    """Straight vertical arrow from y_top downward to y_bot."""
    ax.annotate(
        "", xy=(x, y_bot), xytext=(x, y_top),
        arrowprops=dict(
            arrowstyle="-|>", color=color, lw=lw,
            mutation_scale=9, connectionstyle="arc3,rad=0",
        ), zorder=2,
    )
    if label:
        ax.text(x + lbl_x_off, (y_top + y_bot)/2, label,
                ha="left", va="center",
                fontsize=6.8, color="#555555",
                fontstyle="italic", fontfamily="serif", zorder=6)


def harrow(ax, x_left, x_right, y, color="#666666", lw=1.1, label="", lbl_y_off=0.08):
    """Horizontal arrow from x_left to x_right at height y."""
    ax.annotate(
        "", xy=(x_right, y), xytext=(x_left, y),
        arrowprops=dict(
            arrowstyle="-|>", color=color, lw=lw,
            mutation_scale=9, connectionstyle="arc3,rad=0",
        ), zorder=2,
    )
    if label:
        ax.text((x_left + x_right)/2, y + lbl_y_off, label,
                ha="center", va="bottom",
                fontsize=6.8, color="#555555",
                fontstyle="italic", fontfamily="serif", zorder=6)


def bus(ax, x_list, y_bus, y_from, y_to, color, lw_trunk=1.1, lw_branch=0.9):
    """
    Bus-bar pattern:
      1. Vertical trunk from y_from down to y_bus.
      2. Horizontal bar across all x_list positions.
      3. Short vertical drops from y_bus to y_to at each x.
    x_from is taken as the midpoint of x_list.
    """
    x_from = (x_list[0] + x_list[-1]) / 2
    x_min, x_max = x_list[0], x_list[-1]

    # trunk: single line from source centre down to bus level
    ax.plot([x_from, x_from], [y_from, y_bus],
            color=color, lw=lw_trunk, zorder=2, solid_capstyle="round")

    # horizontal bar
    ax.plot([x_min, x_max], [y_bus, y_bus],
            color=color, lw=lw_trunk, zorder=2, solid_capstyle="round")

    # branch drops (arrow only on the last segment)
    for x in x_list:
        ax.annotate(
            "", xy=(x, y_to), xytext=(x, y_bus),
            arrowprops=dict(
                arrowstyle="-|>", color=color, lw=lw_branch,
                mutation_scale=8, connectionstyle="arc3,rad=0",
            ), zorder=2,
        )


def dashed_bus(ax, x_list, y_bus, y_from, y_to, color, lw=0.85):
    """Same as bus but dashed (for return/feedback flows)."""
    x_from = (x_list[0] + x_list[-1]) / 2
    x_min, x_max = x_list[0], x_list[-1]

    ax.plot([x_from, x_from], [y_from, y_bus],
            color=color, lw=lw, linestyle="dashed", zorder=2)
    ax.plot([x_min, x_max], [y_bus, y_bus],
            color=color, lw=lw, linestyle="dashed", zorder=2)
    for x in x_list:
        ax.annotate(
            "", xy=(x, y_to), xytext=(x, y_bus),
            arrowprops=dict(
                arrowstyle="-|>", color=color, lw=lw,
                linestyle="dashed",
                mutation_scale=7, connectionstyle="arc3,rad=0",
            ), zorder=2,
        )


def band_label(ax, y_centre, label, color):
    ax.text(-0.5, y_centre, label,
            ha="center", va="center", rotation=90,
            fontsize=7.5, color=color,
            fontweight="bold", fontfamily="serif", zorder=6)


# ══════════════════════════════════════════════════════════════════════════════
# DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════

def draw():
    set_style()

    # ── canvas ─────────────────────────────────────────────────────────────
    W, H = 13.0, 11.5
    fig, ax = plt.subplots(figsize=(W, H))
    ax.set_xlim(-0.8, 13.2)
    ax.set_ylim(-0.6, 11.2)
    ax.set_aspect("equal")
    ax.axis("off")

    fig.suptitle("LaunderLens — System Architecture",
                 fontsize=13, fontweight="bold",
                 fontfamily="serif", color="black", y=0.985)

    # ── column grid (4 cols for defenses / metrics) ─────────────────────────
    #  col centres:  C1     C2     C3     C4
    C1, C2, C3, C4 = 1.55, 4.15, 6.75, 9.35
    COLS = [C1, C2, C3, C4]
    CW   = 2.35   # column box width

    # wide-box centre (spans full content area)
    WCX  = (C1 + C4) / 2       # 5.45
    WW   = C4 - C1 + CW        # full span width  ~10.15

    # ── layer band backgrounds ───────────────────────────────────────────────
    def band_bg(yb, yh, lk):
        lc = LAYER[lk]
        ax.add_patch(plt.Rectangle(
            (0.25, yb), 11.70, yh,
            facecolor=lc["face"], edgecolor=lc["edge"],
            linewidth=0.7, zorder=0,
        ))

    # (y_bot, height, layer_key)
    BANDS = [
        (9.70, 1.20, "L1"),
        (7.30, 2.15, "L2"),
        (3.40, 3.65, "L3"),
        (1.20, 1.95, "L4"),
        (0.00, 1.00, "L5"),
    ]
    for yb, yh, lk in BANDS:
        band_bg(yb, yh, lk)

    BAND_LABELS = {
        "L1": (10.30, "Layer 1\nBenchmark"),
        "L2": (8.375, "Layer 2\nPipeline"),
        "L3": (5.225, "Layer 3\nDefenses"),
        "L4": (2.175, "Layer 4\nMetrics"),
        "L5": (0.500, "Layer 5\nOutput"),
    }
    for lk, (yc, lbl) in BAND_LABELS.items():
        band_label(ax, yc, lbl, LAYER[lk]["bar"])

    # ════════════════════════════════════════════════════════════════════════
    # LAYER 1 — three input sources
    # ════════════════════════════════════════════════════════════════════════
    L1_XS = [2.0, 5.45, 8.90]
    L1_Y  = 10.20
    L1_H  = 0.75
    L1_W  = 3.10
    L1_TITLES = ["Benchmark Tasks",    "Attack Registry",       "Local LLM Backend"]
    L1_SUBS   = ["Multi-agent task suites", "Prompt-injection payloads", "OpenAI-compatible inference"]

    for x, t, s in zip(L1_XS, L1_TITLES, L1_SUBS):
        mod(ax, x, L1_Y, L1_W, L1_H, t, s, "L1", bar_h=0.26, title_fs=8.2)

    # ════════════════════════════════════════════════════════════════════════
    # LAYER 2 — Orchestrator (full width), then Trace → Store
    # ════════════════════════════════════════════════════════════════════════
    ORCH_Y = 8.70
    ORCH_H = 0.85
    mod(ax, WCX, ORCH_Y, WW, ORCH_H,
        "Experiment Orchestrator",
        "Builds agent pipeline · injects attack payload · captures message history",
        "L2", bar_h=0.28, title_fs=8.5)

    TRACE_Y = 7.65
    TRACE_H = 0.85
    TRACE_W = 6.50
    STORE_W = 2.80
    mod(ax, 4.50,  TRACE_Y, TRACE_W, TRACE_H,
        "Execution Trace",
        "Hop sequence · tool calls · run config",
        "L2", bar_h=0.28, title_fs=8.2)
    mod(ax, 10.05, TRACE_Y, STORE_W, TRACE_H,
        "Trace Store",
        "JSON audit records",
        "L2", bar_h=0.28, title_fs=8.2)

    # ════════════════════════════════════════════════════════════════════════
    # LAYER 3 — Replay Engine (full width), then 4 defense boxes
    # ════════════════════════════════════════════════════════════════════════
    RE_Y = 5.90
    RE_H = 0.85
    mod(ax, WCX, RE_Y, WW, RE_H,
        "Defense Replay Engine",
        "Post-hoc trajectory replay · issues per-action allow / block verdict · writes decisions to Trace",
        "L3", bar_h=0.28, title_fs=8.5)

    DEF_Y = 4.35
    DEF_H = 1.20
    DEF_TITLES = ["AuthGraph",      "RTBAS",            "CAMEL",            "FIDES"]
    DEF_SUBS   = ["Authorization\ngraph verifier",
                  "Reputation-based\ntaint tracking",
                  "Dual-LLM\nadversarial debate",
                  "Peer-trust\npropagation"]

    # dashed group border
    ax.add_patch(FancyBboxPatch(
        (C1 - CW/2 - 0.12, DEF_Y - DEF_H/2 - 0.12),
        C4 - C1 + CW + 0.24, DEF_H + 0.24,
        boxstyle="round,pad=0.04",
        facecolor="none", edgecolor=LAYER["L3"]["edge"],
        linewidth=0.85, linestyle="dashed", zorder=2,
    ))
    ax.text(WCX, DEF_Y - DEF_H/2 - 0.24,
            "Defense implementations (one of four is selected per run)",
            ha="center", va="top",
            fontsize=6.5, color="#888888",
            fontstyle="italic", fontfamily="serif", zorder=6)

    for x, t, s in zip(COLS, DEF_TITLES, DEF_SUBS):
        mod(ax, x, DEF_Y, CW, DEF_H, t, s, "L3",
            bar_h=0.27, title_fs=8.0, sub_fs=6.9)

    # ════════════════════════════════════════════════════════════════════════
    # LAYER 4 — metric boxes (aligned with defense columns)
    # ════════════════════════════════════════════════════════════════════════
    MET_Y = 2.00
    MET_H = 1.10
    MET_TITLES = ["Attack Success\nRate  (ASR)",
                  "Label Integrity\nScore  (LIS)",
                  "Screener Evasion\nRate  (SER)",
                  "Counterfactual\nOracle"]
    MET_SUBS   = ["Formal security\ncheck per run",
                  "Counterfactual\nfiller test",
                  "Evasion vs.\ncompliance",
                  "Filler substitution\n· stability filter"]

    for x, t, s in zip(COLS, MET_TITLES, MET_SUBS):
        mod(ax, x, MET_Y, CW, MET_H, t, s, "L4",
            bar_h=0.36, title_fs=7.8, sub_fs=6.8)

    # ════════════════════════════════════════════════════════════════════════
    # LAYER 5 — two output boxes
    # ════════════════════════════════════════════════════════════════════════
    OUT_Y = 0.45
    OUT_H = 0.70
    OUT_W = 4.80
    mod(ax, 3.35, OUT_Y, OUT_W, OUT_H,
        "Results & Analysis",
        "Per-attack × per-defense tables · ASR / LIS / SER with confidence intervals",
        "L5", bar_h=0.26, title_fs=8.0, sub_fs=6.8)
    mod(ax, 9.00, OUT_Y, OUT_W, OUT_H,
        "Interactive Trace Viewer",
        "Step-by-step hop inspection · defense label overlay · screener rationale",
        "L5", bar_h=0.26, title_fs=8.0, sub_fs=6.8)

    # ════════════════════════════════════════════════════════════════════════
    # ARROWS — all straight lines, bus-bar for fan-outs
    # ════════════════════════════════════════════════════════════════════════
    C1c = OI["skyblue"]
    C2c = OI["orange"]
    C3c = OI["vermillion"]
    C4c = OI["green"]
    C5c = OI["purple"]

    # ── L1 → Orchestrator  (bus: three sources → one wide box) ─────────────
    # Draw a trunk from each L1 box down to a common y, then a bar, then drop
    BUS_L1 = (L1_Y - L1_H/2 + ORCH_Y + ORCH_H/2) / 2  # midway
    # three vertical lines from each L1 box bottom to BUS_L1
    for x in L1_XS:
        ax.plot([x, x], [L1_Y - L1_H/2, BUS_L1],
                color=C1c, lw=1.0, zorder=2)
    # horizontal bar connecting them
    ax.plot([L1_XS[0], L1_XS[-1]], [BUS_L1, BUS_L1],
            color=C1c, lw=1.0, zorder=2)
    # single drop from bus centre to Orchestrator top
    ax.annotate(
        "", xy=(WCX, ORCH_Y + ORCH_H/2), xytext=(WCX, BUS_L1),
        arrowprops=dict(arrowstyle="-|>", color=C1c, lw=1.1,
                        mutation_scale=9, connectionstyle="arc3,rad=0"),
        zorder=2,
    )

    # ── Orchestrator → Trace (straight vertical) ────────────────────────────
    varrow(ax, 4.50, ORCH_Y - ORCH_H/2, TRACE_Y + TRACE_H/2, color=C2c,
           label="creates", lbl_x_off=0.09)

    # ── Trace → Store (horizontal) ──────────────────────────────────────────
    harrow(ax, 4.50 + TRACE_W/2, 10.05 - STORE_W/2,
           TRACE_Y, color=C2c, label="persists", lbl_y_off=0.08)

    # ── Trace → Replay Engine (straight vertical, centred on trace box) ─────
    varrow(ax, 4.50, TRACE_Y - TRACE_H/2, RE_Y + RE_H/2,
           color=C2c, label="trace", lbl_x_off=0.09)

    # ── Replay Engine → Defenses (bus-bar fan-out) ──────────────────────────
    BUS_RE = RE_Y - RE_H/2 - 0.25   # bus rail just below replay engine
    bus(ax, COLS, BUS_RE,
        y_from = RE_Y - RE_H/2,
        y_to   = DEF_Y + DEF_H/2,
        color  = C3c, lw_trunk=1.1, lw_branch=1.0)
    ax.text(WCX, BUS_RE - 0.04, "dispatches",
            ha="center", va="top",
            fontsize=6.6, color="#555555",
            fontstyle="italic", fontfamily="serif", zorder=6)

    # ── Defenses → Replay Engine (dashed return, offset right of dispatch) ──
    BUS_RET = BUS_RE - 0.18   # slightly below dispatch rail
    dashed_bus(ax,
               [c + 0.18 for c in COLS],   # slight right offset so lines don't overlap
               BUS_RET,
               y_from = DEF_Y + DEF_H/2 + 0.00,
               y_to   = RE_Y - RE_H/2 - 0.01,
               color  = C3c, lw=0.75)
    ax.text(WCX + 2.5, BUS_RET - 0.04, "verdicts",
            ha="center", va="top",
            fontsize=6.6, color="#888888",
            fontstyle="italic", fontfamily="serif", zorder=6)

    # ── Defenses → Metrics (straight vertical per column) ───────────────────
    for x in COLS:
        varrow(ax, x, DEF_Y - DEF_H/2, MET_Y + MET_H/2, color=C3c, lw=1.0)

    # ── Counterfactual Oracle → LIS (horizontal within L4) ──────────────────
    harrow(ax, C4 - CW/2, C2 + CW/2, MET_Y + 0.12,
           color=C4c, label="ground truth", lbl_y_off=0.07)

    # ── Metrics → Output (bus to two outputs) ───────────────────────────────
    BUS_MET = MET_Y - MET_H/2 - 0.18
    # ASR, LIS, SER → Results & Analysis
    for x in [C1, C2, C3]:
        ax.plot([x, x], [MET_Y - MET_H/2, BUS_MET],
                color=C4c, lw=0.9, zorder=2)
    ax.plot([C1, C3], [BUS_MET, BUS_MET], color=C4c, lw=0.9, zorder=2)
    ax.annotate(
        "", xy=(3.35, OUT_Y + OUT_H/2), xytext=(3.35, BUS_MET),
        arrowprops=dict(arrowstyle="-|>", color=C4c, lw=1.0,
                        mutation_scale=9, connectionstyle="arc3,rad=0"),
        zorder=2,
    )

    # Counterfactual Oracle → Trace Viewer
    varrow(ax, C4, MET_Y - MET_H/2, OUT_Y + OUT_H/2,
           color=C5c, lw=1.0, label="trace refs", lbl_x_off=0.10)

    # ════════════════════════════════════════════════════════════════════════
    # Legend
    # ════════════════════════════════════════════════════════════════════════
    handles = [
        mpatches.Patch(facecolor=LAYER[lk]["bar"],
                       edgecolor="#888888", linewidth=0.5, label=lbl)
        for lk, lbl in [("L1","Benchmark"), ("L2","Pipeline"),
                         ("L3","Defenses"),  ("L4","Metrics"), ("L5","Output")]
    ]
    ax.legend(handles=handles, loc="lower center",
              bbox_to_anchor=(0.5, -0.05), ncol=5,
              frameon=True, framealpha=1.0,
              edgecolor="#CCCCCC", facecolor="white",
              prop={"family": "serif", "size": 8.5})

    fig.tight_layout(rect=[0.04, 0.03, 1.0, 0.97])
    save(fig, "architecture_diagram")


if __name__ == "__main__":
    print("\nGenerating architecture diagram...")
    draw()
    print("Done.")
