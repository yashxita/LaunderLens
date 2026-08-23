"""
base.py  —  the Defense interface.

Plain-English idea
------------------
A "defense" watches an agent run and decides whether each action is allowed.
Different defences (AuthGraph, RTBAS, ...) work very differently inside, but they
all answer the same two questions for LaunderLens:

  1. For each tool call the agent makes: ALLOW or BLOCK it?
  2. For the data behind that call: what TRUST LABEL does the defence assign
     (trusted / untrusted), and what did its screener decide?

LaunderLens records those answers into each Hop (defense_label, screener_decision,
screener_reason) so the LIS oracle can later check whether those labels were HONEST.

Every concrete defence subclasses Defense and implements `review`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ActionDecision:
    """The defence's verdict on ONE tool call the agent wants to make."""
    allow: bool                                  # True = let it run, False = block it
    trust_label: Optional[str] = None            # "trusted" | "untrusted" | None
    screener_decision: Optional[str] = None      # e.g. "keep" | "block" | "extra_step_ok" | "suspicious"
    reason: str = ""                             # the defence's stated reason (for logging + LIS)
    layer: Optional[str] = None                  # which internal layer decided (e.g. "hard_block", "param_check")


@dataclass
class DefenseContext:
    """
    Everything a defence is allowed to see when reviewing an action.
    (Different defences use different subsets of this.)
    """
    user_prompt: str                             # the ORIGINAL user instruction (trusted)
    tool_catalog: list[dict] = field(default_factory=list)   # available tools: name, params, description
    prior_actions: list[dict] = field(default_factory=list)  # tool calls already made this run
    observations: dict[str, str] = field(default_factory=dict)  # tool_name -> raw observation text seen so far
    current_action: dict = field(default_factory=dict)       # {"tool": ..., "args": {...}} being reviewed


class Defense:
    """
    Base class. A defence reviews actions one at a time as the agent runs.

    Subclasses implement `review(context) -> ActionDecision`. They may also
    override `setup(user_prompt, tool_catalog)` to do one-time planning before
    the run (e.g. AuthGraph builds its authorization graph there).
    """

    name: str = "none"

    def setup(self, user_prompt: str, tool_catalog: list[dict]) -> None:
        """Optional one-time preparation before the agent starts (default: nothing)."""
        return None

    def review(self, context: DefenseContext) -> ActionDecision:
        """Decide on the current action. Default: allow everything, label nothing."""
        return ActionDecision(allow=True, trust_label=None,
                              screener_decision="keep", reason="no-op base defense")


class NoDefense(Defense):
    """Explicit 'no defence' — allows everything. Useful as a control in experiments."""
    name = "none"