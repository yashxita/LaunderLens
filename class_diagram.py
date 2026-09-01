"""
class_diagram.py  —  LaunderLens UML class diagram.

Academic style:
  - White background, DejaVu Serif, Okabe-Ito palette, 300 dpi.
  - Four columns with WIDE inter-column gaps (connectors pass cleanly through).
  - Strict grid: all connector lines are horizontal or vertical only.
  - UML structure: «stereotype» / Name bar / attributes / methods.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

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
    "black":      "#111111",
}
GRP = {
    "data":     {"face": "#EAF4FF", "edge": "#9DC8E8", "bar": OI["blue"]},
    "core":     {"face": "#FFF8EC", "edge": "#E8C870", "bar": OI["orange"]},
    "defense":  {"face": "#FFF0E8", "edge": "#E8A890", "bar": OI["vermillion"]},
    "decision": {"face": "#E6F7F2", "edge": "#70C8A8", "bar": OI["green"]},
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


# ─────────────────────────────────────────────────────────────────────────────
# UML box
# ─────────────────────────────────────────────────────────────────────────────
def uml_class(ax, cx, top_y, w,
              stereotype, name, attrs, methods,
              grp="data",
              stereo_fs=6.0, name_fs=8.0,
              attr_fs=6.8, meth_fs=6.8,
              row_h=0.22, pad=0.10):
    """
    Draw a UML class box whose TOP is at top_y.
    Returns (top_y, bottom_y, cx).
    """
    lc = GRP[grp]
    stereo_h = row_h * 0.85
    name_h   = row_h * 1.15
    attr_h   = len(attrs)  * row_h + pad
    meth_h   = len(methods) * row_h + pad if methods else 0
    total_h  = stereo_h + name_h + attr_h + meth_h
    bot_y    = top_y - total_h

    # outer shell
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, bot_y), w, total_h,
        boxstyle="round,pad=0.02",
        facecolor=lc["face"], edgecolor=lc["edge"],
        linewidth=1.2, zorder=3,
    ))

    # stereotype strip
    y_stereo_mid = top_y - stereo_h / 2
    ax.text(cx, y_stereo_mid, stereotype,
            ha="center", va="center",
            fontsize=stereo_fs, color="#555555",
            fontstyle="italic", fontfamily="serif", zorder=5)

    # name bar
    y_name_top = top_y - stereo_h
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, y_name_top - name_h), w, name_h,
        boxstyle="round,pad=0.01",
        facecolor=lc["bar"], edgecolor="none",
        zorder=4, clip_on=False,
    ))
    ax.text(cx, y_name_top - name_h / 2, name,
            ha="center", va="center",
            fontsize=name_fs, color="white",
            fontweight="bold", fontfamily="serif", zorder=5)

    # divider
    y_attr_top = y_name_top - name_h
    ax.plot([cx - w/2, cx + w/2], [y_attr_top, y_attr_top],
            color=lc["edge"], lw=0.7, zorder=4)

    # attributes
    for k, attr in enumerate(attrs):
        ty = y_attr_top - pad/2 - (k + 0.6) * row_h
        ax.text(cx - w/2 + 0.10, ty, attr,
                ha="left", va="center",
                fontsize=attr_fs, color="#222222",
                fontfamily="serif", zorder=5)

    # methods
    if methods:
        y_meth_top = y_attr_top - attr_h
        ax.plot([cx - w/2, cx + w/2], [y_meth_top, y_meth_top],
                color=lc["edge"], lw=0.7, zorder=4)
        for k, meth in enumerate(methods):
            ty = y_meth_top - pad/2 - (k + 0.6) * row_h
            ax.text(cx - w/2 + 0.10, ty, meth,
                    ha="left", va="center",
                    fontsize=meth_fs, color=OI["blue"],
                    fontfamily="serif", zorder=5)

    return top_y, bot_y


# ─────────────────────────────────────────────────────────────────────────────
# Drawing helpers
# ─────────────────────────────────────────────────────────────────────────────
def hline(ax, x1, x2, y, color, lw=0.9, ls="solid"):
    ax.plot([x1, x2], [y, y], color=color, lw=lw, linestyle=ls,
            solid_capstyle="round", zorder=6)


def vline(ax, x, y1, y2, color, lw=0.9, ls="solid"):
    ax.plot([x, x], [y1, y2], color=color, lw=lw, linestyle=ls,
            solid_capstyle="round", zorder=6)


def arrow_h(ax, x1, x2, y, color, label="", above=True, fs=6.5):
    """Horizontal arrow from (x1,y) to (x2,y) with arrowhead at x2."""
    ax.annotate(
        "", xy=(x2, y), xytext=(x1, y),
        arrowprops=dict(
            arrowstyle="-|>", color=color, lw=0.9,
            mutation_scale=8,
            connectionstyle="arc3,rad=0",
        ), zorder=2,
    )
    if label:
        lbl_dy = 0.08 if above else -0.13
        ax.text((x1 + x2)/2, y + lbl_dy, label,
                ha="center", va="bottom" if above else "top",
                fontsize=fs, color="#555555",
                fontstyle="italic", fontfamily="serif", zorder=6)


def arrow_v(ax, x, y1, y2, color, label="", right=True, fs=6.5):
    """Vertical arrow from (x,y1) to (x,y2) with arrowhead at y2."""
    ax.annotate(
        "", xy=(x, y2), xytext=(x, y1),
        arrowprops=dict(
            arrowstyle="-|>", color=color, lw=0.9,
            mutation_scale=8,
            connectionstyle="arc3,rad=0",
        ), zorder=2,
    )
    if label:
        lbl_dx = 0.08 if right else -0.08
        ax.text(x + lbl_dx, (y1 + y2)/2, label,
                ha="left" if right else "right", va="center",
                fontsize=fs, color="#555555",
                fontstyle="italic", fontfamily="serif", zorder=6)


def arrow_v_open(ax, x, y1, y2, color, fs=6.5):
    """Open-triangle (inheritance) vertical arrow."""
    ax.annotate(
        "", xy=(x, y2), xytext=(x, y1),
        arrowprops=dict(
            arrowstyle="-|>", color=color, lw=1.1,
            mutation_scale=10,
            connectionstyle="arc3,rad=0",
        ), zorder=2,
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
def draw():
    set_style()

    # ── Canvas ──────────────────────────────────────────────────────────────
    # 4 columns with WIDE gaps so connector channels are roomy.
    #   Col 0  Data Model      cx = 2.0
    #   Col 1  Pipeline Core   cx = 7.0    gap = 3.25 units on each side
    #   Col 2  Decision Types  cx = 12.0   gap = 3.25 units on each side
    #   Col 3  Defense         cx = 17.0   gap = 3.25 units on each side
    #
    # Box width = 3.8 units  → right edge C0 = 3.9  left edge C1 = 5.1
    #                            gap channel = 3.9..5.1 = 1.2 units WIDE → plenty of room

    C0, C1, C2, C3 = 2.0, 7.0, 12.0, 17.0
    W = 3.80          # box width
    FW = 20.5         # figure width (inches)
    FH = 13.0         # figure height

    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.set_xlim(-0.5, 19.5)
    ax.set_ylim(-0.8, 13.0)
    ax.set_aspect("equal")
    ax.axis("off")

    fig.suptitle("LaunderLens  —  Class Diagram",
                 fontsize=14, fontweight="bold",
                 fontfamily="serif", color=OI["black"], y=0.990)

    RH  = 0.215    # row height
    PAD = 0.10

    # ── Column 0 — Data Model ───────────────────────────────────────────────
    RC_TOP = 11.50
    rc_top, rc_bot = uml_class(
        ax, C0, RC_TOP, W,
        "«dataclass»", "RunConfig",
        ["+ model: str",
         "+ model_id: str",
         "+ seed: int",
         "+ suite: str",
         "+ attack: Optional[str]",
         "+ defense: Optional[str]",
         "+ code_commit: str"],
        [], grp="data", row_h=RH, pad=PAD)

    HOP_TOP = 7.20
    hop_top, hop_bot = uml_class(
        ax, C0, HOP_TOP, W,
        "«dataclass»", "Hop",
        ["+ hop_index: int",
         "+ agent_role: str",
         "+ output_text: str",
         "+ contains_untrusted_source: bool",
         "+ defense_label: Optional[str]",
         "+ screener_decision: Optional[str]",
         "+ ground_truth_influence: Optional[bool]"],
        [], grp="data", row_h=RH, pad=PAD)

    CF_TOP = 3.20
    cf_top, cf_bot = uml_class(
        ax, C0, CF_TOP, W,
        "«dataclass»", "Counterfactual",
        ["+ fillers: list[str]",
         "+ action_changed_per_filler: list[bool]",
         "+ usable_for_ground_truth: Optional[bool]"],
        [], grp="data", row_h=RH, pad=PAD)

    # ── Column 1 — Pipeline Core ─────────────────────────────────────────────
    TRACE_TOP = 10.20
    tr_top, tr_bot = uml_class(
        ax, C1, TRACE_TOP, W,
        "«dataclass»", "Trace",
        ["+ config: RunConfig",
         "+ run_id: str",
         "+ timestamp: str",
         "+ hops: list[Hop]",
         "+ all_actions: list[dict]",
         "+ attack_succeeded: Optional[bool]",
         "+ defense_decisions: list[dict]",
         "+ lis_verdict: Optional[str]"],
        ["+ add_hop(hop): None",
         "+ save(logs_dir): str",
         "+ load(path): Trace",
         "+ to_dict(): dict"],
        grp="core", row_h=RH, pad=PAD)

    # ── Column 2 — Decision Types ────────────────────────────────────────────
    AD_TOP = 11.30
    ad_top, ad_bot = uml_class(
        ax, C2, AD_TOP, W,
        "«dataclass»", "ActionDecision",
        ["+ allow: bool",
         "+ trust_label: Optional[str]",
         "+ screener_decision: Optional[str]",
         "+ layer: Optional[str]",
         "+ reason: str"],
        [], grp="decision", row_h=RH, pad=PAD)

    DC_TOP = 7.30
    dc_top, dc_bot = uml_class(
        ax, C2, DC_TOP, W,
        "«dataclass»", "DefenseContext",
        ["+ user_prompt: str",
         "+ tool_catalog: list[dict]",
         "+ prior_actions: list[dict]",
         "+ observations: dict[str, str]",
         "+ current_action: dict"],
        [], grp="decision", row_h=RH, pad=PAD)

    # ── Column 3 — Defense Hierarchy ─────────────────────────────────────────
    DEF_TOP = 12.50
    def_top, def_bot = uml_class(
        ax, C3, DEF_TOP, W,
        "«abstract»", "Defense",
        ["+ name: str"],
        ["+ setup(user_prompt, catalog): None",
         "+ review(context): ActionDecision"],
        grp="defense", row_h=RH, pad=PAD)

    AG_TOP = 10.50
    ag_top, ag_bot = uml_class(
        ax, C3, AG_TOP, W,
        "«class»", "AuthGraph",
        ["+ steps: list[AuthStep]",
         "+ authorized_tools: set[str]"],
        ["+ setup(...): None",
         "+ review(ctx): ActionDecision"],
        grp="defense", row_h=RH, pad=PAD)

    RT_TOP = 7.80
    rt_top, rt_bot = uml_class(
        ax, C3, RT_TOP, W,
        "«class»", "RTBAS",
        ["+ trust_threshold: float"],
        ["+ review(ctx): ActionDecision"],
        grp="defense", row_h=RH, pad=PAD)

    CM_TOP = 5.40
    cm_top, cm_bot = uml_class(
        ax, C3, CM_TOP, W,
        "«class»", "CAMEL / FIDES",
        ["+ model_id: str"],
        ["+ review(ctx): ActionDecision"],
        grp="defense", row_h=RH, pad=PAD)

    # ═════════════════════════════════════════════════════════════════════════
    # CONNECTORS
    # All lines are horizontal (hline) or vertical (vline).
    # Channel positions:
    #   x_ch01 = midpoint of C0 right (3.9) and C1 left (5.1)  →  4.50
    #   x_ch12 = midpoint of C1 right (8.9) and C2 left (10.1) →  9.50
    #   x_ch23 = midpoint of C2 right (13.9) and C3 left (15.1)→ 14.50
    # ═════════════════════════════════════════════════════════════════════════
    BLUE  = OI["blue"]
    GRN   = OI["green"]
    VER   = OI["vermillion"]

    x_ch01 = (C0 + W/2 + C1 - W/2) / 2   # = (3.9 + 5.1)/2 = 4.50
    x_ch23 = (C2 + W/2 + C3 - W/2) / 2   # = (13.9+15.1)/2 = 14.50

    C0R = C0 + W/2    # right edge of col-0 boxes
    C1L = C1 - W/2    # left  edge of Trace box
    C1R = C1 + W/2    # right edge of Trace box
    C2L = C2 - W/2    # left  edge of Decision boxes
    C2R = C2 + W/2    # right edge of Decision boxes
    C3L = C3 - W/2    # left  edge of Defense boxes

    # ── RunConfig → Trace  (config: 1) ───────────────────────────────────
    # horizontal from RC right → channel x, then vertical to Trace entry, then horizontal into Trace
    rc_mid_y = (rc_top + rc_bot) / 2
    rc_entry_y = TRACE_TOP - 1.60    # y inside Trace (below name bar)
    hline(ax, C0R, x_ch01, rc_mid_y, BLUE)
    vline(ax, x_ch01, rc_mid_y, rc_entry_y, BLUE)
    arrow_h(ax, x_ch01, C1L, rc_entry_y, BLUE, label="config  1", above=True)

    # ── Hop → Trace  (hops: *) ────────────────────────────────────────────
    hop_mid_y = (hop_top + hop_bot) / 2
    hop_entry_y = TRACE_TOP - 2.80   # a bit lower inside Trace
    hline(ax, C0R, x_ch01, hop_mid_y, BLUE)
    vline(ax, x_ch01, hop_mid_y, hop_entry_y, BLUE)
    arrow_h(ax, x_ch01, C1L, hop_entry_y, BLUE, label="hops  *", above=True)

    # ── Counterfactual → Trace  (counterfactual: 1) ───────────────────────
    cf_mid_y = (cf_top + cf_bot) / 2
    cf_entry_y = TRACE_TOP - 3.80    # near bottom of Trace
    hline(ax, C0R, x_ch01, cf_mid_y, BLUE)
    vline(ax, x_ch01, cf_mid_y, cf_entry_y, BLUE)
    arrow_h(ax, x_ch01, C1L, cf_entry_y, BLUE, label="counterfactual  1", above=True)

    # ── Trace → ActionDecision  (returns: ActionDecision) ─────────────────
    # horizontal from Trace right → channel x12 → vertical up → horizontal into AD
    ad_mid_y = (ad_top + ad_bot) / 2
    x_ch12 = (C1 + W/2 + C2 - W/2) / 2
    tr_exit_y = TRACE_TOP - 2.20    # y on Trace right edge level
    hline(ax, C1R, x_ch12, tr_exit_y, GRN)
    vline(ax, x_ch12, tr_exit_y, ad_mid_y, GRN)
    arrow_h(ax, x_ch12, C2L, ad_mid_y, GRN, label="returns", above=True)

    # ── DefenseContext → ActionDecision  (context) ────────────────────────
    # vertical up in column 2, from DC top → AD bottom
    dc_mid_y = (dc_top + dc_bot) / 2
    arrow_v(ax, C2, dc_top, ad_bot, GRN, label="context", right=True)

    # ── Defense subclasses inherit Defense ────────────────────────────────
    # Trunk runs on the LEFT side of col-3 so it stays within the canvas.
    # Pattern:
    #   each subclass left edge → stub left  → trunk (one vertical line from
    #   lowest stub down to Defense bottom)  → arrowhead + horiz into Defense.
    trunk_x = C3 - W/2 - 0.30    # left of all defense boxes

    ag_mid_y = (ag_top + ag_bot) / 2
    rt_mid_y = (rt_top + rt_bot) / 2
    cm_mid_y = (cm_top + cm_bot) / 2

    # horizontal stubs from each box left edge → trunk
    hline(ax, trunk_x, C3 - W/2, ag_mid_y, VER)
    hline(ax, trunk_x, C3 - W/2, rt_mid_y, VER)
    hline(ax, trunk_x, C3 - W/2, cm_mid_y, VER)

    # single vertical trunk connecting all three stubs (bottom of lowest → top of highest)
    vline(ax, trunk_x, cm_mid_y, ag_mid_y, VER)

    # vertical from AG stub y up to just below Defense bottom, then arrowhead
    arrow_v(ax, trunk_x, ag_mid_y, def_bot, VER)
    hline(ax, trunk_x, C3 - W/2, def_bot, VER)

    ax.text(trunk_x - 0.06, (ag_mid_y + def_bot) / 2, "extends",
            ha="right", va="center", fontsize=6.5,
            color="#777777", fontstyle="italic", fontfamily="serif", zorder=6)

    # ── Defense.review uses ActionDecision  (uses: dashed) ───────────────
    uses_y = (ad_top + ad_bot) / 2 + 0.10   # slightly above AD midpoint
    hline(ax, C3L, x_ch23, uses_y, VER, ls="dashed")
    arrow_h(ax, x_ch23, C2R, uses_y, VER, label="uses", above=True)

    # ═════════════════════════════════════════════════════════════════════════
    # Column headers
    # ═════════════════════════════════════════════════════════════════════════
    for cx, lbl, col in [
        (C0, "Data Model",        GRP["data"]["bar"]),
        (C1, "Pipeline Core",     GRP["core"]["bar"]),
        (C2, "Decision Types",    GRP["decision"]["bar"]),
        (C3, "Defense Hierarchy", GRP["defense"]["bar"]),
    ]:
        ax.text(cx, 12.75, lbl,
                ha="center", va="center",
                fontsize=9.5, color=col,
                fontweight="bold", fontfamily="serif", zorder=6)
        ax.plot([cx - W/2 + 0.12, cx + W/2 - 0.12],
                [12.55, 12.55], color=col, lw=1.4, zorder=5)

    # ═════════════════════════════════════════════════════════════════════════
    # Legend
    # ═════════════════════════════════════════════════════════════════════════
    handles = [
        mpatches.Patch(facecolor=GRP["data"]["bar"],     edgecolor="#aaa", lw=0.5, label="Data model"),
        mpatches.Patch(facecolor=GRP["core"]["bar"],     edgecolor="#aaa", lw=0.5, label="Pipeline core"),
        mpatches.Patch(facecolor=GRP["decision"]["bar"], edgecolor="#aaa", lw=0.5, label="Decision types"),
        mpatches.Patch(facecolor=GRP["defense"]["bar"],  edgecolor="#aaa", lw=0.5, label="Defense hierarchy"),
    ]
    ax.legend(handles=handles, loc="lower center",
              bbox_to_anchor=(0.5, -0.045), ncol=4,
              frameon=True, framealpha=1.0,
              edgecolor="#CCCCCC", facecolor="white",
              prop={"family": "serif", "size": 9})

    fig.tight_layout(rect=[0.01, 0.03, 1.0, 0.97])
    save(fig, "class_diagram")


if __name__ == "__main__":
    print("\nGenerating class diagram...")
    draw()
    print("Done.")
