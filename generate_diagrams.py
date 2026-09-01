"""
generate_diagrams.py  —  generates all 6 report diagrams for LaunderLens.

Diagrams produced:
  1. data_flow_diagram.png      — DFD (Level 1)
  2. use_case_diagram.png       — UML Use Case
  3. class_diagram.png          — UML Class Diagram
  4. sequence_diagram.png       — UML Sequence Diagram
  5. gantt_chart.png            — Gantt Chart (project timeline)
  6. architecture_diagram.png   — System Architecture

Run from the repo root:
    python generate_diagrams.py

Output: diagrams/ folder (created automatically).
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, ArrowStyle
from matplotlib.lines import Line2D
import numpy as np

# ── output folder ──────────────────────────────────────────────────────────────
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diagrams")
os.makedirs(OUT, exist_ok=True)

# ── shared colour palette ──────────────────────────────────────────────────────
BG      = "#0F1117"
CARD    = "#1A1D2E"
ACCENT1 = "#6C63FF"   # violet
ACCENT2 = "#FF6584"   # rose
ACCENT3 = "#43D9AD"   # teal
ACCENT4 = "#F9C74F"   # gold
ACCENT5 = "#4CC9F0"   # sky blue
WHITE   = "#FFFFFF"
LIGHT   = "#C8D0E7"
GREY    = "#3A3F5C"

DPI = 180

# ──────────────────────────────────────────────────────────────────────────────
#  HELPER: draw a rounded-rect box with label
# ──────────────────────────────────────────────────────────────────────────────
def fancy_box(ax, cx, cy, w, h, label, sublabel="",
              facecolor=CARD, edgecolor=ACCENT1, fontsize=9,
              text_color=WHITE, radius=0.08, lw=1.5, zorder=3):
    box = FancyBboxPatch((cx - w/2, cy - h/2), w, h,
                         boxstyle=f"round,pad={radius}",
                         facecolor=facecolor, edgecolor=edgecolor,
                         linewidth=lw, zorder=zorder)
    ax.add_patch(box)
    if sublabel:
        ax.text(cx, cy + h * 0.12, label, ha="center", va="center",
                fontsize=fontsize, fontweight="bold", color=text_color, zorder=zorder+1)
        ax.text(cx, cy - h * 0.25, sublabel, ha="center", va="center",
                fontsize=fontsize - 1.5, color=LIGHT, zorder=zorder+1,
                style="italic")
    else:
        ax.text(cx, cy, label, ha="center", va="center",
                fontsize=fontsize, fontweight="bold", color=text_color, zorder=zorder+1)
    return box


def arrow(ax, x1, y1, x2, y2, label="", color=ACCENT1, lw=1.4, zorder=2,
          style="->", label_offset=(0, 0.08)):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color,
                                lw=lw, connectionstyle="arc3,rad=0.0"),
                zorder=zorder)
    if label:
        mx, my = (x1+x2)/2 + label_offset[0], (y1+y2)/2 + label_offset[1]
        ax.text(mx, my, label, ha="center", va="bottom",
                fontsize=7, color=ACCENT4, zorder=zorder+1)


def setup_ax(fig, ax, title):
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title(title, color=WHITE, fontsize=13, fontweight="bold", pad=14,
                 fontfamily="monospace")


# ══════════════════════════════════════════════════════════════════════════════
# 1. DATA FLOW DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def draw_dfd():
    fig, ax = plt.subplots(figsize=(16, 10))
    setup_ax(fig, ax, "LaunderLens — Data Flow Diagram (Level 1)")
    ax.set_xlim(0, 16); ax.set_ylim(0, 10)

    def ext(cx, cy, label, color=ACCENT2):
        for dx, dy in [(0.04, 0.04)]:
            r = FancyBboxPatch((cx-1.1+dx, cy-0.42+dy), 2.2, 0.84,
                               boxstyle="square,pad=0.04",
                               facecolor=BG, edgecolor=color,
                               linewidth=1, zorder=2)
            ax.add_patch(r)
        fancy_box(ax, cx, cy, 2.2, 0.84, label,
                  facecolor="#1F1030", edgecolor=color, fontsize=8.5, lw=1.8)

    def proc(cx, cy, pid, label, color=ACCENT1):
        ellipse = mpatches.Ellipse((cx, cy), 2.6, 1.1,
                                   facecolor="#151B38", edgecolor=color,
                                   linewidth=1.8, zorder=3)
        ax.add_patch(ellipse)
        ax.text(cx, cy + 0.18, f"P{pid}", ha="center", va="center",
                fontsize=7, color=ACCENT4, fontweight="bold", zorder=4)
        ax.text(cx, cy - 0.15, label, ha="center", va="center",
                fontsize=7.5, color=WHITE, fontweight="bold", zorder=4)

    def store(cx, cy, sid, label, color=ACCENT3):
        ax.plot([cx-1.3, cx+1.3], [cy+0.32, cy+0.32], color=color, lw=1.5, zorder=3)
        ax.plot([cx-1.3, cx+1.3], [cy-0.32, cy-0.32], color=color, lw=1.5, zorder=3)
        ax.plot([cx-1.3, cx-1.3], [cy-0.32, cy+0.32], color=color, lw=1.5, zorder=3)
        rect = plt.Rectangle((cx-1.3, cy-0.32), 2.6, 0.64,
                              facecolor="#0B1A20", edgecolor="none", zorder=2)
        ax.add_patch(rect)
        ax.text(cx-1.0, cy, f"D{sid}", ha="left", va="center",
                fontsize=7, color=ACCENT3, fontweight="bold", zorder=4)
        ax.text(cx+0.1, cy, label, ha="center", va="center",
                fontsize=7.5, color=WHITE, zorder=4)

    # ── entities ──
    ext(1.3, 8.5, "Researcher")
    ext(14.7, 8.5, "LLM Agent\n(Ollama)")
    ext(1.3, 1.5, "AgentDojo\nBenchmark")
    ext(14.7, 1.5, "Attack\nPayload")

    # ── processes ──
    proc(4.5, 8.5, "1", "Run Config\n& CLI")
    proc(8.0, 8.5, "2", "Pipeline\nRunner")
    proc(11.5, 8.5, "3", "Message\nCapture")
    proc(4.5, 5.0, "4", "Defense\nReplay")
    proc(8.0, 5.0, "5", "LIS Oracle\n& Metrics")
    proc(11.5, 5.0, "6", "Counterfactual\nRunner")
    proc(8.0, 1.8, "7", "Results\n& Scoring")

    # ── stores ──
    store(4.5, 2.8, "1", "Trace Logs (JSON)", ACCENT3)
    store(11.5, 2.8, "2", "Defense Decisions", ACCENT3)

    # ── flows ──
    def fl(x1, y1, x2, y2, lbl="", off=(0, 0.1), rad=0.0, col=LIGHT):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color=col, lw=1.3,
                                   connectionstyle=f"arc3,rad={rad}"), zorder=2)
        if lbl:
            ax.text((x1+x2)/2+off[0], (y1+y2)/2+off[1], lbl,
                    ha="center", va="bottom", fontsize=6.5, color=ACCENT4, zorder=5)

    fl(2.4, 8.5,  3.2, 8.5,  "run params")
    fl(5.8, 8.5,  6.7, 8.5,  "task config")
    fl(9.3, 8.5, 10.2, 8.5,  "messages")
    fl(13.6, 8.35, 13.3, 8.35, "tool calls", rad=-0.3)
    fl(14.0, 8.65, 12.8, 8.65, "observations", rad=0.3)
    fl(2.4, 1.5,  3.2, 1.8,  "suite/tasks")
    fl(14.0, 1.5, 12.8, 1.6, "injections")
    fl(11.5, 7.95, 11.5, 6.5, "hop list", off=(0.3, 0))
    fl(11.5, 6.5, 11.5, 3.12, "action list", off=(0.3, 0))
    fl(4.5, 7.95, 4.5, 3.12, "trace ref",  off=(0.3, 0))
    fl(5.8, 5.0,  6.7, 5.0,  "trace+actions")
    fl(9.3, 5.0, 10.2, 5.0,  "counterfactual requests", off=(0, 0.12))
    fl(8.0, 4.45, 8.0, 2.15, "oracle verdicts", off=(0.35, 0))
    fl(10.2, 5.0, 9.3, 5.0,  "filler traces",   off=(0, -0.15))
    fl(4.5, 2.48, 5.8, 2.0,  "load trace")
    fl(10.2, 2.8, 6.7, 5.2,  "defence decisions", rad=0.1)
    fl(8.0, 1.45, 8.0, 0.8,  "ASR / LIS / SER report")

    # legend
    for i, (col, lbl) in enumerate([(ACCENT2, "External Entity"),
                                     (ACCENT1, "Process"),
                                     (ACCENT3, "Data Store"),
                                     (LIGHT,   "Data Flow")]):
        ax.plot([0.3], [9.65-i*0.3], "s" if i < 3 else ">",
                color=col, markersize=7 if i < 3 else 6, zorder=5)
        ax.text(0.65, 9.65-i*0.3, lbl, va="center",
                fontsize=7, color=LIGHT, zorder=5)

    plt.tight_layout(pad=0.5)
    path = os.path.join(OUT, "data_flow_diagram.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  DFD saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. USE CASE DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def draw_use_case():
    fig, ax = plt.subplots(figsize=(16, 11))
    setup_ax(fig, ax, "LaunderLens — Use Case Diagram")
    ax.set_xlim(0, 16); ax.set_ylim(0, 11)

    sys_box = FancyBboxPatch((3.0, 0.4), 10.0, 10.1,
                             boxstyle="round,pad=0.1",
                             facecolor="#12152A", edgecolor=ACCENT1,
                             linewidth=2, zorder=1)
    ax.add_patch(sys_box)
    ax.text(8.0, 10.3, "<<system>>  LaunderLens", ha="center", va="center",
            fontsize=10, fontweight="bold", color=ACCENT1, zorder=2)

    def actor(cx, cy, label, color=ACCENT3):
        head = plt.Circle((cx, cy+1.0), 0.22, color=color, zorder=4)
        ax.add_patch(head)
        ax.plot([cx, cx], [cy+0.78, cy+0.15], color=color, lw=1.8, zorder=4)
        ax.plot([cx-0.35, cx+0.35], [cy+0.55, cy+0.55], color=color, lw=1.8, zorder=4)
        ax.plot([cx, cx-0.3], [cy+0.15, cy-0.25], color=color, lw=1.8, zorder=4)
        ax.plot([cx, cx+0.3], [cy+0.15, cy-0.25], color=color, lw=1.8, zorder=4)
        ax.text(cx, cy-0.45, label, ha="center", va="top",
                fontsize=8, color=color, fontweight="bold", zorder=4)

    def uc(cx, cy, label, color=ACCENT1, w=2.5, h=0.7):
        ellipse = mpatches.Ellipse((cx, cy), w, h,
                                   facecolor=CARD, edgecolor=color,
                                   linewidth=1.6, zorder=3)
        ax.add_patch(ellipse)
        lines = label.split("\n")
        for k, ln in enumerate(lines):
            offset = (k - (len(lines)-1)/2) * 0.22
            ax.text(cx, cy - offset, ln, ha="center", va="center",
                    fontsize=7.2, color=WHITE, fontweight="bold", zorder=4)

    actor(1.3, 7.0, "Researcher", ACCENT3)
    actor(1.3, 3.0, "Researcher", ACCENT3)
    actor(14.7, 7.0, "LLM Agent\n(Ollama)", ACCENT5)
    actor(14.7, 3.0, "AgentDojo\nBenchmark", ACCENT4)

    uc(6.5, 9.5,  "Configure & Launch\nExperiment",      ACCENT1, 2.8, 0.8)
    uc(6.5, 8.1,  "Select Attack /\nDefense Combo",      ACCENT1, 2.8, 0.8)
    uc(6.5, 6.6,  "Run Agent Task\n(Runner.py)",         ACCENT1, 2.8, 0.8)
    uc(6.5, 5.2,  "Capture Trace\n(Hop Sequence)",       ACCENT1, 2.8, 0.8)
    uc(9.5, 9.5,  "Inject Prompt-\nInjection Payload",   ACCENT2, 2.8, 0.8)
    uc(9.5, 8.1,  "Execute Tool\nCalls",                 ACCENT5, 2.8, 0.8)
    uc(9.5, 6.6,  "Return Tool\nObservations",           ACCENT5, 2.8, 0.8)
    uc(6.5, 3.8,  "Apply Defense\n(AuthGraph/RTBAS)",    ACCENT1, 2.8, 0.8)
    uc(9.5, 3.8,  "Assign Trust\nLabels per Hop",        ACCENT1, 2.8, 0.8)
    uc(6.5, 2.4,  "Run Counterfactual\nFillers",         ACCENT1, 2.8, 0.8)
    uc(9.5, 2.4,  "Compute LIS Oracle\nVerdicts",        ACCENT3, 2.8, 0.8)
    uc(8.0, 1.0,  "Score ASR / LIS / SER",               ACCENT4, 2.8, 0.8)

    def assoc(x1, y1, bx, by, col=GREY):
        ax.plot([x1, bx], [y1, by], color=col, lw=1.2, zorder=2)

    for uy in [9.5, 8.1, 6.6, 5.2]:
        assoc(1.8, 7.5, 5.12, uy, ACCENT3)
    for uy in [3.8, 2.4]:
        assoc(1.8, 3.5, 5.12, uy, ACCENT3)
    for uy in [8.1, 6.6]:
        assoc(14.3, 7.5, 10.88, uy, ACCENT5)
    assoc(14.3, 3.5, 10.88, 9.5, ACCENT4)
    assoc(14.3, 3.5, 10.88, 2.4, ACCENT4)

    def include(x1, y1, x2, y2, lbl="<<include>>"):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color=ACCENT4,
                                   lw=1.1, linestyle="dashed"), zorder=2)
        ax.text((x1+x2)/2+0.05, (y1+y2)/2+0.12, lbl,
                ha="center", va="bottom", fontsize=6, color=ACCENT4, zorder=5)

    include(7.84, 9.5,  9.08, 9.5)
    include(7.84, 8.1,  9.08, 8.1)
    include(7.84, 6.6,  9.08, 6.6)
    include(7.84, 3.8,  9.08, 3.8)
    include(7.84, 2.4,  9.08, 2.4)
    include(6.5,  3.44, 6.5,  2.76)
    include(9.5,  2.04, 8.6,  1.36)

    plt.tight_layout(pad=0.4)
    path = os.path.join(OUT, "use_case_diagram.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Use Case saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. CLASS DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def draw_class_diagram():
    fig, ax = plt.subplots(figsize=(18, 12))
    setup_ax(fig, ax, "LaunderLens — Class Diagram")
    ax.set_xlim(0, 18); ax.set_ylim(0, 12)

    def class_box(cx, cy, name, stereotype="", attrs=(), methods=(), color=ACCENT1, w=3.6, row_h=0.38):
        n_rows = 1 + len(attrs) + 1 + len(methods)
        total_h = n_rows * row_h + 0.2
        top = cy + total_h / 2

        outer = FancyBboxPatch((cx-w/2, cy-total_h/2), w, total_h,
                               boxstyle="round,pad=0.05",
                               facecolor=CARD, edgecolor=color,
                               linewidth=1.8, zorder=3)
        ax.add_patch(outer)

        hdr_h = row_h * 1.1 + 0.05
        hdr = FancyBboxPatch((cx-w/2, top - hdr_h), w, hdr_h,
                             boxstyle="round,pad=0.03",
                             facecolor=color+"44", edgecolor="none", zorder=4)
        ax.add_patch(hdr)

        y_cur = top - row_h * 0.55
        if stereotype:
            ax.text(cx, y_cur+0.14, f"<<{stereotype}>>", ha="center", va="center",
                    fontsize=6, color=color, zorder=5, style="italic")
        ax.text(cx, y_cur - (0.14 if stereotype else 0), name, ha="center", va="center",
                fontsize=8.5, color=WHITE, fontweight="bold", zorder=5)

        div_y = top - hdr_h - 0.02
        ax.plot([cx-w/2, cx+w/2], [div_y, div_y], color=color, lw=0.8, zorder=4)

        y_cur = div_y - row_h * 0.5
        for a in attrs:
            ax.text(cx-w/2+0.12, y_cur, a, ha="left", va="center",
                    fontsize=6.8, color=LIGHT, zorder=5, fontfamily="monospace")
            y_cur -= row_h

        ax.plot([cx-w/2, cx+w/2], [y_cur+row_h*0.35, y_cur+row_h*0.35],
                color=GREY, lw=0.6, zorder=4)

        for m in methods:
            ax.text(cx-w/2+0.12, y_cur, m, ha="left", va="center",
                    fontsize=6.8, color=ACCENT5, zorder=5, fontfamily="monospace")
            y_cur -= row_h

        return total_h

    def rel(x1, y1, x2, y2, kind="assoc", lbl="", col=GREY, rad=0.0):
        if kind == "inherit":
            # hollow triangle (UML generalisation)
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=1.5,
                                       connectionstyle=f"arc3,rad={rad}"), zorder=2)
        elif kind == "dep":
            # dashed line with open arrowhead (UML dependency)
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle="->", color=col, lw=1.2,
                                       connectionstyle=f"arc3,rad={rad}",
                                       linestyle="dashed"), zorder=2)
        else:
            # plain association line
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle="-", color=col, lw=1.0,
                                       connectionstyle=f"arc3,rad={rad}"), zorder=2)
        if lbl:
            ax.text((x1+x2)/2+0.05, (y1+y2)/2+0.12, lbl,
                    ha="center", va="bottom", fontsize=6.5, color=ACCENT4, zorder=6)

    class_box(3.0, 10.5, "RunConfig", stereotype="dataclass",
              attrs=["+ model: str", "+ model_id: str", "+ seed: int",
                     "+ suite: str", "+ attack: Optional[str]",
                     "+ defense: Optional[str]", "+ code_commit: str"],
              methods=[], color=ACCENT1, w=3.8)

    class_box(3.0, 6.8, "Hop", stereotype="dataclass",
              attrs=["+ hop_index: int", "+ agent_role: str",
                     "+ output_text: str",
                     "+ contains_untrusted_source: bool",
                     "+ defense_label: Optional[str]",
                     "+ screener_decision: Optional[str]",
                     "+ ground_truth_influence: Optional[bool]"],
              methods=[], color=ACCENT1, w=3.8)

    class_box(3.0, 3.5, "Counterfactual", stereotype="dataclass",
              attrs=["+ fillers: list[str]",
                     "+ action_changed_per_filler: list[bool]",
                     "+ usable_for_ground_truth: Optional[bool]"],
              methods=[], color=ACCENT1, w=3.8)

    class_box(8.5, 8.0, "Trace", stereotype="dataclass",
              attrs=["+ config: RunConfig", "+ run_id: str",
                     "+ timestamp: str", "+ hops: list[Hop]",
                     "+ all_actions: list[dict]",
                     "+ attack_succeeded: Optional[bool]",
                     "+ defense_decisions: list[dict]",
                     "+ lis_verdict: Optional[str]"],
              methods=["+ add_hop(hop): None",
                       "+ save(logs_dir): str",
                       "+ load(path): Trace",
                       "+ to_dict(): dict"],
              color=ACCENT3, w=3.8)

    class_box(14.0, 10.2, "Defense", stereotype="abstract",
              attrs=["+ name: str"],
              methods=["+ setup(user_prompt, catalog): None",
                       "+ review(context): ActionDecision"],
              color=ACCENT2, w=3.8)

    class_box(14.0, 7.8, "AuthGraph", stereotype="class",
              attrs=["+ steps: list[AuthStep]",
                     "+ authorized_tools: set[str]"],
              methods=["+ setup(...): None",
                       "+ review(ctx): ActionDecision"],
              color=ACCENT2, w=3.8)

    class_box(14.0, 5.6, "RTBAS", stereotype="class",
              attrs=["+ trust_threshold: float"],
              methods=["+ review(ctx): ActionDecision"],
              color=ACCENT2, w=3.8)

    class_box(14.0, 3.6, "CAMEL / FIDES", stereotype="class",
              attrs=["+ model_id: str"],
              methods=["+ review(ctx): ActionDecision"],
              color=ACCENT2, w=3.8)

    class_box(8.5, 4.2, "ActionDecision", stereotype="dataclass",
              attrs=["+ allow: bool", "+ trust_label: Optional[str]",
                     "+ screener_decision: Optional[str]",
                     "+ layer: Optional[str]", "+ reason: str"],
              methods=[], color=ACCENT5, w=3.8)

    class_box(8.5, 1.6, "DefenseContext", stereotype="dataclass",
              attrs=["+ user_prompt: str", "+ tool_catalog: list[dict]",
                     "+ prior_actions: list[dict]",
                     "+ observations: dict[str,str]",
                     "+ current_action: dict"],
              methods=[], color=ACCENT5, w=3.8)

    rel(8.5-1.9, 8.6,   3.0+1.9, 10.0,  kind="assoc", lbl="config 1",     col=LIGHT)
    rel(8.5-1.9, 8.0,   3.0+1.9, 6.8,   kind="assoc", lbl="hops *",       col=LIGHT)
    rel(8.5-1.9, 7.4,   3.0+1.9, 4.1,   kind="assoc", lbl="counterfactual 1", col=LIGHT)
    rel(14.0-1.9, 9.8,  14.0-1.9, 8.3,  kind="inherit", col=ACCENT2)
    rel(14.0-1.9, 9.8,  14.0-1.9+0.0, 6.1,  kind="inherit", col=ACCENT2)
    rel(14.0-1.9, 9.8,  14.0-1.9+0.0, 4.1,  kind="inherit", col=ACCENT2)
    rel(14.0-1.9, 7.8,  8.5+1.9, 4.6,   kind="dep", lbl="returns", col=ACCENT4)
    rel(8.5+1.9,  4.2,  14.0-1.9, 5.6,  kind="dep", lbl="uses",   col=ACCENT5, rad=0.2)
    rel(8.5+1.9,  1.9,  14.0-1.9, 5.3,  kind="dep", lbl="context", col=ACCENT5)

    plt.tight_layout(pad=0.4)
    path = os.path.join(OUT, "class_diagram.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Class Diagram saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. SEQUENCE DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def draw_sequence():
    fig, ax = plt.subplots(figsize=(18, 13))
    setup_ax(fig, ax, "LaunderLens — Sequence Diagram (Attack + Defense Replay Flow)")
    ax.set_xlim(0, 18); ax.set_ylim(0, 13)

    participants = [
        ("Researcher",    1.5,  ACCENT3),
        ("Runner\n.py",   4.5,  ACCENT1),
        ("AgentDojo\nPipeline", 7.5, ACCENT5),
        ("LLM Agent\n(Ollama)", 10.5, ACCENT4),
        ("Defense\nModule",     13.5, ACCENT2),
        ("Metrics\nScorer",     16.5, ACCENT3),
    ]

    TOP = 12.5
    BOTTOM = 0.5

    for label, x, color in participants:
        hdr = FancyBboxPatch((x-0.85, TOP-0.5), 1.7, 0.8,
                             boxstyle="round,pad=0.06",
                             facecolor=color+"33", edgecolor=color,
                             linewidth=1.6, zorder=4)
        ax.add_patch(hdr)
        lines = label.split("\n")
        for i, ln in enumerate(lines):
            ax.text(x, TOP-0.1-(i*0.24), ln, ha="center", va="center",
                    fontsize=7.5, color=WHITE, fontweight="bold", zorder=5)
        ax.plot([x, x], [TOP-0.5, BOTTOM], color=color+"66",
                lw=1.0, linestyle="--", zorder=1)

    def activation(x, y_start, y_end, color):
        h = y_start - y_end
        box = plt.Rectangle((x-0.12, y_end), 0.24, h,
                             facecolor=color+"55", edgecolor=color,
                             linewidth=1.0, zorder=3)
        ax.add_patch(box)

    def msg(x1, x2, y, label, col=LIGHT, ret=False):
        style = "<-" if ret else "-|>"
        ls = "dashed" if ret else "solid"
        ax.annotate("", xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle=style, color=col, lw=1.3,
                                   linestyle=ls), zorder=3)
        ax.text((x1+x2)/2, y+0.13, label, ha="center", va="bottom",
                fontsize=6.8, color=col if not ret else ACCENT4, zorder=4,
                style="italic" if ret else "normal")

    def note_box(x, y, w, h, text, color=ACCENT4):
        nb = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05",
                            facecolor=color+"22", edgecolor=color,
                            linewidth=1.0, zorder=5)
        ax.add_patch(nb)
        for i, ln in enumerate(text.split("\n")):
            ax.text(x+w/2, y+h-0.18-i*0.22, ln, ha="center", va="top",
                    fontsize=6.5, color=color, zorder=6)

    # Phase 1: Setup
    note_box(0.1, 11.45, 3.5, 0.55, "Phase 1 — Configure & Launch", ACCENT1)
    msg(1.5, 4.5, 11.3, "run_one(suite, task, attack, defense)", ACCENT3)
    msg(4.5, 7.5, 10.9, "get_suite() / load_attack()")
    msg(7.5, 4.5, 10.5, "suite, attacker returned", col=ACCENT5, ret=True)

    # Phase 2: Execution
    note_box(0.1, 9.75, 3.5, 0.55, "Phase 2 — Agent Execution", ACCENT5)
    activation(4.5, 10.5, 7.6, ACCENT1)
    activation(7.5, 10.9, 7.6, ACCENT5)
    msg(4.5, 7.5, 10.1, "run_task_with_pipeline(task, injections)", ACCENT1)
    activation(10.5, 10.1, 7.6, ACCENT4)
    msg(7.5, 10.5, 9.7, "system prompt + injected tool data", ACCENT5)
    msg(10.5, 7.5, 9.3, "tool_call: read_file(bill.txt)", col=ACCENT4, ret=True)
    msg(7.5, 10.5, 8.9, "observation: <INFORMATION> pay attacker </INFORMATION>", ACCENT5)
    msg(10.5, 7.5, 8.5, "tool_call: send_money(attacker_iban)", col=ACCENT2, ret=True)
    msg(7.5, 10.5, 8.1, "tool result: OK", ACCENT5)
    msg(7.5, 4.5,  7.7, "utility=True, security=True, messages[]", col=ACCENT5, ret=True)

    # Phase 3: Trace capture
    note_box(0.1, 7.0, 3.5, 0.55, "Phase 3 — Trace Capture", ACCENT3)
    msg(4.5, 1.5, 6.8, "_messages_to_hops() -> Trace.save()", ACCENT1)
    msg(1.5, 4.5, 6.4, "trace.json path returned", col=ACCENT3, ret=True)

    # Phase 4: Defense replay
    note_box(0.1, 5.6, 3.5, 0.55, "Phase 4 — Defense Replay", ACCENT2)
    activation(13.5, 6.4, 4.4, ACCENT2)
    msg(4.5, 13.5, 6.1, "apply_defense_to_trace(trace, AuthGraph)", ACCENT1)
    msg(13.5, 4.5, 5.7, "defense.setup(user_prompt, tool_catalog)", ACCENT2)
    msg(13.5, 4.5, 5.3, "for action in all_actions: defense.review(ctx)", ACCENT2)
    msg(4.5, 13.5, 4.9, "ActionDecision(allow, trust_label, layer, reason)", col=ACCENT1, ret=True)
    msg(13.5, 4.5, 4.4, "trace.defense_decisions written", col=ACCENT2, ret=True)

    # Phase 5: Metrics
    note_box(0.1, 3.7, 3.5, 0.55, "Phase 5 — Score & Report", ACCENT4)
    activation(16.5, 4.4, 0.9, ACCENT3)
    msg(4.5, 16.5, 3.9, "compute ASR / LIS-sink / SER", ACCENT1)
    msg(16.5, 4.5, 3.5, "asr, lis, ser scores", col=ACCENT3, ret=True)
    msg(16.5, 1.5, 3.1, "results report", col=ACCENT3, ret=True)

    plt.tight_layout(pad=0.4)
    path = os.path.join(OUT, "sequence_diagram.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Sequence Diagram saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. GANTT CHART
# ══════════════════════════════════════════════════════════════════════════════
def draw_gantt():
    fig, ax = plt.subplots(figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    tasks = [
        ("Phase 1: Foundation",   "Repo setup & environment config",              0, 1,  ACCENT3),
        ("Phase 1: Foundation",   "AgentDojo integration & smoke test",           0, 2,  ACCENT3),
        ("Phase 1: Foundation",   "Trace data model  (trace.py)",                 1, 1,  ACCENT3),
        ("Phase 1: Foundation",   "Pipeline runner   (runner.py)",                1, 2,  ACCENT3),
        ("Phase 1: Foundation",   "Milestone 1 — first clean trace",              2, 1,  ACCENT3),

        ("Phase 2: LIS Oracle",   "actions_differ() metric",                      3, 1,  ACCENT1),
        ("Phase 2: LIS Oracle",   "Counterfactual runner",                        3, 2,  ACCENT1),
        ("Phase 2: LIS Oracle",   "ASR scorer  (asr_score.py)",                   4, 1,  ACCENT1),
        ("Phase 2: LIS Oracle",   "LIS scorer  (lis_score.py)",                   4, 2,  ACCENT1),
        ("Phase 2: LIS Oracle",   "Batch experiment driver",                      5, 1,  ACCENT1),
        ("Phase 2: LIS Oracle",   "Milestone 2 — poisoned trace confirmed",       5, 1,  ACCENT1),

        ("Phase 3: Defenses",     "AuthGraph reimplementation",                   6, 2,  ACCENT2),
        ("Phase 3: Defenses",     "RTBAS reimplementation",                       7, 2,  ACCENT2),
        ("Phase 3: Defenses",     "apply_defense_to_trace()",                     8, 1,  ACCENT2),
        ("Phase 3: Defenses",     "Defense-in-loop LIS-sink scoring",             8, 2,  ACCENT2),
        ("Phase 3: Defenses",     "Milestone 3 — defense baseline",               9, 1,  ACCENT2),

        ("Phase 4: Attacks",      "attribution_forgery attack",                  10, 2,  ACCENT4),
        ("Phase 4: Attacks",      "label_join attack",                           11, 2,  ACCENT4),
        ("Phase 4: Attacks",      "First result table (ASR + LIS + SER)",        12, 1,  ACCENT4),
        ("Phase 4: Attacks",      "GO / NO-GO checkpoint",                       12, 1,  ACCENT4),

        ("Phase 5: Paper",        "Cohen's kappa human agreement study",         13, 2,  ACCENT5),
        ("Phase 5: Paper",        "Paper writing  (intro + method sections)",    13, 3,  ACCENT5),
        ("Phase 5: Paper",        "Experiments on GPT-4o-class model",           14, 2,  ACCENT5),
        ("Phase 5: Paper",        "Results & discussion sections",               15, 2,  ACCENT5),
        ("Phase 5: Paper",        "Submission & artifact release",               16, 1,  ACCENT5),
    ]

    total_weeks = 18
    n_tasks = len(tasks)

    for i in range(n_tasks):
        bg_col = "#16192C" if i % 2 == 0 else "#12152A"
        ax.barh(i, total_weeks, left=0, height=0.9, color=bg_col, zorder=1)

    phase_drawn = set()
    for i, (phase, task, start, dur, col) in enumerate(tasks):
        if phase not in phase_drawn:
            indices = [j for j, (p, *_) in enumerate(tasks) if p == phase]
            mid = (min(indices) + max(indices)) / 2
            ax.text(-0.3, mid, phase, ha="right", va="center",
                    fontsize=8, color=col, fontweight="bold", zorder=6)
            if min(indices) > 0:
                ax.axhline(min(indices)-0.5, color=GREY, lw=0.8, zorder=2)
            phase_drawn.add(phase)

    for i, (phase, task, start, dur, col) in enumerate(tasks):
        ax.barh(i, dur, left=start, height=0.72, color=col,
                alpha=0.85, zorder=3, edgecolor=BG, linewidth=0.5)
        ax.text(start + dur/2, i, task, ha="center", va="center",
                fontsize=6.8, color=WHITE, fontweight="bold", zorder=4)

    today_week = 17
    ax.axvline(today_week, color=ACCENT2, lw=2, linestyle="--", zorder=5)
    ax.text(today_week+0.1, n_tasks-0.3, "Today", color=ACCENT2,
            fontsize=8, fontweight="bold", zorder=6)

    ax.set_xlim(-7.5, total_weeks + 0.5)
    ax.set_ylim(-0.6, n_tasks)
    ax.set_yticks([])
    ax.set_xticks(range(total_weeks + 1))
    ax.set_xticklabels([f"W{w}" for w in range(total_weeks + 1)],
                       color=LIGHT, fontsize=7.5)
    ax.tick_params(colors=LIGHT, which="both")
    ax.set_xlabel("Project Timeline (Weeks)", color=LIGHT, fontsize=10, labelpad=8)
    ax.set_title("LaunderLens — Project Gantt Chart", color=WHITE,
                 fontsize=13, fontweight="bold", pad=14, fontfamily="monospace")

    for x in range(total_weeks + 1):
        ax.axvline(x, color=GREY, lw=0.4, zorder=0)

    for col, lbl in [(ACCENT3, "Phase 1: Foundation"),
                     (ACCENT1, "Phase 2: LIS Oracle"),
                     (ACCENT2, "Phase 3: Defenses"),
                     (ACCENT4, "Phase 4: Attacks"),
                     (ACCENT5, "Phase 5: Paper")]:
        ax.barh(-0.5, 0, color=col, label=lbl)
    ax.legend(loc="lower right", fontsize=8, facecolor=CARD,
              edgecolor=GREY, labelcolor=WHITE)

    for spine in ax.spines.values():
        spine.set_edgecolor(GREY)

    plt.tight_layout(pad=0.6)
    path = os.path.join(OUT, "gantt_chart.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Gantt Chart saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. ARCHITECTURE DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def draw_architecture():
    fig, ax = plt.subplots(figsize=(18, 12))
    setup_ax(fig, ax, "LaunderLens — System Architecture Diagram")
    ax.set_xlim(0, 18); ax.set_ylim(0, 12)

    def layer_bg(y_bot, h, label, color):
        rect = plt.Rectangle((0.3, y_bot), 17.4, h,
                              facecolor=color+"18", edgecolor=color+"55",
                              linewidth=1.2, zorder=1)
        ax.add_patch(rect)
        ax.text(0.55, y_bot + h/2, label, ha="left", va="center",
                fontsize=7.5, color=color, fontweight="bold", rotation=90, zorder=2)

    def module(cx, cy, w, h, title, subtitle="", color=ACCENT1):
        box = FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                             boxstyle="round,pad=0.08",
                             facecolor=CARD, edgecolor=color,
                             linewidth=1.8, zorder=3)
        ax.add_patch(box)
        hdr = FancyBboxPatch((cx-w/2, cy+h/2-0.42), w, 0.42,
                             boxstyle="round,pad=0.04",
                             facecolor=color+"44", edgecolor="none", zorder=4)
        ax.add_patch(hdr)
        ax.text(cx, cy+h/2-0.21, title, ha="center", va="center",
                fontsize=8, color=WHITE, fontweight="bold", zorder=5)
        if subtitle:
            lines = subtitle.split("\n")
            for k, ln in enumerate(lines):
                offset = (k - (len(lines)-1)/2) * 0.24
                ax.text(cx, cy - offset + 0.0, ln, ha="center", va="center",
                        fontsize=6.8, color=LIGHT, zorder=5)

    def conn(x1, y1, x2, y2, lbl="", col=GREY, rad=0.0, bi=False):
        if bi:
            # draw two arrows for bidirectional
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=1.4,
                                       connectionstyle=f"arc3,rad={rad}"), zorder=2)
            ax.annotate("", xy=(x1, y1), xytext=(x2, y2),
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=1.4,
                                       connectionstyle=f"arc3,rad={rad}"), zorder=2)
        else:
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=1.4,
                                       connectionstyle=f"arc3,rad={rad}"), zorder=2)
        if lbl:
            ax.text((x1+x2)/2+0.05, (y1+y2)/2+0.15, lbl,
                    ha="center", va="bottom", fontsize=6.5, color=ACCENT4, zorder=6)

    layer_bg(0.3,  2.0,  "L5\nOutput",    ACCENT4)
    layer_bg(2.3,  2.2,  "L4\nMetrics",   ACCENT3)
    layer_bg(4.5,  2.5,  "L3\nDefenses",  ACCENT2)
    layer_bg(7.0,  2.4,  "L2\nPipeline",  ACCENT1)
    layer_bg(9.4,  2.6,  "L1\nBenchmark", ACCENT5)

    # Layer 1: Benchmark
    module(4.5,  10.7, 2.8, 1.0, "AgentDojo",       "Banking / Travel\nTask Suites",      ACCENT5)
    module(9.0,  10.7, 2.8, 1.0, "Attack Registry", "important_instructions\nattrib_forgery", ACCENT2)
    module(13.5, 10.7, 2.8, 1.0, "Ollama Server",   "llama3.1:8b\nqwen2.5:14b",           ACCENT4)

    # Layer 2: Pipeline
    module(4.5,  8.2,  2.8, 1.4, "runner.py",   "run_one()\nAgentPipeline\nTraceLogger",   ACCENT1)
    module(9.0,  8.2,  2.8, 1.4, "trace.py",    "Trace / Hop\nRunConfig\nCounterfactual",  ACCENT1)
    module(13.5, 8.2,  2.8, 1.4, "Logs (JSON)", "logs/<run_id>.json\nall_actions\nhops[]", ACCENT3)

    # Layer 3: Defenses
    module(3.0,  5.75, 2.2, 1.3, "AuthGraph",        "3-layer auth\ngraph",             ACCENT2)
    module(5.8,  5.75, 2.2, 1.3, "RTBAS",            "Reputation-based\ntaint analysis", ACCENT2)
    module(8.6,  5.75, 2.2, 1.3, "CAMEL",            "LLM-based\nscreener",             ACCENT2)
    module(11.4, 5.75, 2.2, 1.3, "FIDES",            "Trust propagation",               ACCENT2)
    module(14.5, 5.75, 2.8, 1.3, "apply_defense.py", "Replay engine\nActionDecision\nper hop", ACCENT2)

    # Layer 4: Metrics
    module(3.5,  3.4,  2.5, 1.0, "asr_score.py",     "Attack Success\nRate (ASR)",       ACCENT3)
    module(7.0,  3.4,  2.5, 1.0, "lis_score.py",     "Label Integrity\nScore (LIS)",     ACCENT3)
    module(10.5, 3.4,  2.5, 1.0, "counterfactual.py","Filler oracle\nground truth",       ACCENT3)
    module(14.0, 3.4,  2.5, 1.0, "ser_score.py",     "Screener Evasion\nRate (SER)",     ACCENT3)

    # Layer 5: Output
    module(5.5,  1.3,  3.2, 0.9, "Result Tables",     "ASR / LIS / SER\nper attack x defense", ACCENT4)
    module(12.5, 1.3,  3.2, 0.9, "Trace Inspector",   "trace_inspector.html\nvisual debugger",  ACCENT4)

    # Connections L1 -> L2
    conn(4.5, 10.2,  4.5, 8.9,  "suite/tasks",    ACCENT5)
    conn(9.0, 10.2,  9.0, 8.9,  "injections",     ACCENT2)
    conn(13.5, 10.2, 13.5, 8.9, "tool responses", ACCENT4)
    # L2 internal
    conn(5.9, 8.2,  7.6, 8.2,  "Trace obj", ACCENT1, bi=True)
    conn(10.4, 8.2, 12.1, 8.2, "save()",    ACCENT1)
    # L2 -> L3
    conn(9.0, 7.5,  14.5, 6.4, "Trace",           ACCENT1)
    conn(14.5, 6.1, 13.5, 7.5, "defense_decisions", ACCENT2)
    # L3 internal
    conn(4.1,  5.75, 4.69, 5.75, "", ACCENT2)
    conn(6.9,  5.75, 7.49, 5.75, "", ACCENT2)
    conn(9.7,  5.75, 10.29, 5.75, "", ACCENT2)
    conn(12.5, 5.75, 13.1, 5.75, "", ACCENT2)
    # L3 -> L4
    conn(14.5, 5.1, 14.0, 3.9, "decisions[]",   ACCENT2)
    conn(9.0, 5.1,  7.0, 3.9,  "oracle",        ACCENT3)
    conn(3.0, 5.1,  3.5, 3.9,  "attack flag",   ACCENT2)
    conn(11.4, 5.1, 10.5, 3.9, "counterfactual", ACCENT3)
    # L4 -> L5
    conn(7.0, 2.9,  5.5, 1.75, "LIS", ACCENT3)
    conn(10.5, 2.9, 12.5, 1.75,"trace refs", ACCENT4)
    conn(3.5, 2.9,  5.5, 1.8,  "ASR", ACCENT3)
    conn(14.0, 2.9, 12.5, 1.8, "SER", ACCENT3)

    # Legend
    legend_x = 15.5
    for i, (col, lbl) in enumerate([(ACCENT5, "L1: Benchmark"),
                                     (ACCENT1, "L2: Pipeline"),
                                     (ACCENT2, "L3: Defenses"),
                                     (ACCENT3, "L4: Metrics"),
                                     (ACCENT4, "L5: Output")]):
        ax.plot([legend_x], [11.6-i*0.38], "s", color=col, markersize=9, zorder=6)
        ax.text(legend_x+0.25, 11.6-i*0.38, lbl, va="center",
                fontsize=7.5, color=LIGHT, zorder=6)

    plt.tight_layout(pad=0.4)
    path = os.path.join(OUT, "architecture_diagram.png")
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  Architecture saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{'='*60}")
    print("  LaunderLens — Diagram Generator")
    print(f"  Output directory: {OUT}")
    print(f"{'='*60}\n")

    print("Generating diagrams...")
    draw_dfd()
    draw_use_case()
    draw_class_diagram()
    draw_sequence()
    draw_gantt()
    draw_architecture()

    print(f"\n{'='*60}")
    print("  All 6 diagrams generated successfully!")
    print(f"  Open: {OUT}")
    print(f"{'='*60}\n")
