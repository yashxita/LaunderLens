"""
_draw.py  —  shared drawing helpers for the defence architecture diagrams.

Same visual language as ../architecture_diagram.py: Okabe-Ito palette, serif
fonts, white background, 300 dpi, straight arrows only.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIGDIR = os.path.join(ROOT, "diagrams")
os.makedirs(FIGDIR, exist_ok=True)

OI = {
    "blue": "#0072B2", "orange": "#E69F00", "green": "#009E73",
    "vermillion": "#D55E00", "purple": "#CC79A7", "skyblue": "#56B4E9",
    "grey": "#666666",
}
# face / edge / title-bar colours per role
ROLE = {
    "trusted":   {"face": "#EAF4FF", "edge": "#9DC8E8", "bar": OI["blue"]},
    "untrusted": {"face": "#FDEDEC", "edge": "#E8A890", "bar": OI["vermillion"]},
    "agent":     {"face": "#F2F2F2", "edge": "#B0B0B0", "bar": "#555555"},
    "novel":     {"face": "#FFF4E0", "edge": "#E8C870", "bar": OI["orange"]},
    "adopted":   {"face": "#E6F7F2", "edge": "#70C8A8", "bar": OI["green"]},
    "llm":       {"face": "#F5F0FA", "edge": "#C8A8D8", "bar": OI["purple"]},
    "audit":     {"face": "#F5F0FA", "edge": "#C8A8D8", "bar": OI["purple"]},
}
OUTCOME = {"BLOCK": OI["vermillion"], "ENDORSE": OI["green"],
           "ESCALATE": OI["orange"], "ALLOW": OI["green"]}


def set_style():
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["DejaVu Serif"],
        "figure.facecolor": "white", "axes.facecolor": "white",
        "savefig.facecolor": "white", "savefig.bbox": "tight",
        "savefig.dpi": 300,
    })


def canvas(w, h, title, xlim, ylim):
    set_style()
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(*xlim)
    ax.set_ylim(*ylim)
    ax.set_aspect("equal")
    ax.axis("off")
    fig.subplots_adjust(left=0.01, right=0.99, top=0.96, bottom=0.03)
    fig.suptitle(title, fontsize=13, fontweight="bold", y=0.995)
    return fig, ax


def box(ax, cx, cy, w, h, title, sub="", role="trusted",
        bar_h=0.34, title_fs=8.6, sub_fs=7.0, dashed=False):
    c = ROLE[role]
    ax.add_patch(FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h, boxstyle="round,pad=0.02",
        facecolor=c["face"], edgecolor=c["edge"], linewidth=1.2,
        linestyle="--" if dashed else "-", zorder=3))
    ax.add_patch(FancyBboxPatch(
        (cx - w / 2, cy + h / 2 - bar_h), w, bar_h, boxstyle="round,pad=0.01",
        facecolor=c["bar"], edgecolor="none", zorder=4))
    ax.text(cx, cy + h / 2 - bar_h / 2, title, ha="center", va="center",
            fontsize=title_fs, color="white", fontweight="bold", zorder=5)
    if sub:
        ax.text(cx, cy - bar_h / 2, sub, ha="center", va="center",
                fontsize=sub_fs, color="#333333", fontstyle="italic",
                linespacing=1.35, zorder=5)


def tag(ax, cx, cy, kind, text, w=3.6, h=0.62):
    """Small outcome tag (BLOCK / ENDORSE / ESCALATE)."""
    col = OUTCOME[kind]
    ax.add_patch(FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h, boxstyle="round,pad=0.02",
        facecolor="white", edgecolor=col, linewidth=1.4, zorder=3))
    ax.text(cx - w / 2 + 0.15, cy, kind, ha="left", va="center",
            fontsize=7.8, color=col, fontweight="bold", zorder=5)
    ax.text(cx - w / 2 + 1.35, cy, text, ha="left", va="center",
            fontsize=6.6, color="#333333", zorder=5, linespacing=1.25)


def arrow(ax, x0, y0, x1, y1, label="", color=OI["grey"], lw=1.1,
          dashed=False, lbl_off=(0.08, 0.0), lbl_ha="left"):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(
        arrowstyle="-|>", color=color, lw=lw, mutation_scale=9,
        linestyle="--" if dashed else "-", connectionstyle="arc3,rad=0"),
        zorder=2)
    if label:
        ax.text((x0 + x1) / 2 + lbl_off[0], (y0 + y1) / 2 + lbl_off[1], label,
                ha=lbl_ha, va="center", fontsize=6.6, color="#555555",
                fontstyle="italic", zorder=6)


def line(ax, xs, ys, color=OI["grey"], lw=1.1, dashed=False):
    ax.plot(xs, ys, color=color, lw=lw, linestyle="--" if dashed else "-",
            zorder=2, solid_capstyle="round")


def legend(ax, items, loc="lower left", ncol=4):
    handles = [Patch(facecolor=ROLE[r]["face"], edgecolor=ROLE[r]["bar"],
                     label=lab) for r, lab in items]
    ax.legend(handles=handles, loc=loc, ncol=ncol, fontsize=7.2,
              frameon=False, bbox_to_anchor=(0.0, -0.035))


def save(fig, stem):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(FIGDIR, f"{stem}.{ext}"))
    print(f"  Wrote diagrams/{stem}.png + .pdf")
