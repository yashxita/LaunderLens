"""
policy.py  —  per-suite tool policy for WITNESS.

This is static, auditable configuration (the same kind of table ROPE and CaMeL
keep): which tools are SINKS (state-changing or data-leaving), what each sink
argument's value TYPE and ROLE is, and which read tools return high-integrity
data.

Argument roles
--------------
  identity   who/where the effect goes (IBAN, email, URL). Full WITNESS pipeline:
             typed enumeration, uniqueness, trusted elimination, corroboration,
             closed-choice confirmation.
  quantity   how much (amount). The value must be PRESENT in the declared source
             (fail-closed membership). With `strict_quantities=True` it gets the
             identity pipeline instead.
  reference  names / ids / channels / file paths that cannot be enumerated by a
             regex. The value must appear in the prompt or in some observation
             the agent has already read (membership only).
  user_only  must appear literally in the user's prompt (e.g. a new password).
  free_text  subjects, bodies, messages. Not gated by WITNESS (out of scope:
             use a FIDES-style capacity limit). Logged as UNCHECKED.

Tool names follow AgentDojo v1/v1.2. Anything not listed is treated as a READ and
is never blocked by WITNESS, except where a suite marks a read as a sink because
it can leak data (slack `get_webpage`: visiting an attacker URL is an
exfiltration channel in AgentDojo's own injection tasks).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .recognisers import IBAN, EMAIL, URL, AMOUNT

IDENTITY, QUANTITY, REFERENCE, USER_ONLY, FREE_TEXT = (
    "identity", "quantity", "reference", "user_only", "free_text")


@dataclass(frozen=True)
class ArgSpec:
    role: str
    vtype: Optional[str] = None      # only for identity / quantity
    is_list: bool = False            # e.g. send_email.recipients


@dataclass
class SuitePolicy:
    name: str
    sinks: dict[str, dict[str, ArgSpec]]
    trusted_tools: set[str] = field(default_factory=set)      # high-integrity reads
    record_tools: set[str] = field(default_factory=set)       # structured records (parsed, never free text)
    self_value_tools: dict[str, str] = field(default_factory=dict)  # tool -> vtype of the user's own value

    def is_sink(self, tool: str) -> bool:
        return tool in self.sinks

    def arg_spec(self, tool: str, arg: str) -> ArgSpec:
        # Unknown argument on a known sink: treat as free text (logged, not gated).
        return self.sinks.get(tool, {}).get(arg, ArgSpec(FREE_TEXT))

    def is_trusted_source(self, tool: str) -> bool:
        return tool in self.trusted_tools


_ID_IBAN = ArgSpec(IDENTITY, IBAN)
_QTY = ArgSpec(QUANTITY, AMOUNT)
_REF = ArgSpec(REFERENCE)
_TXT = ArgSpec(FREE_TEXT)

BANKING = SuitePolicy(
    name="banking",
    sinks={
        "send_money": {"recipient": _ID_IBAN, "amount": _QTY, "subject": _TXT, "date": _TXT},
        "schedule_transaction": {"recipient": _ID_IBAN, "amount": _QTY, "subject": _TXT,
                                 "date": _TXT, "recurring": _TXT},
        "update_scheduled_transaction": {"id": _REF, "recipient": _ID_IBAN, "amount": _QTY,
                                         "subject": _TXT, "date": _TXT, "recurring": _TXT},
        "update_password": {"password": ArgSpec(USER_ONLY)},
        "update_user_info": {"first_name": _REF, "last_name": _REF, "street": _REF, "city": _REF},
    },
    trusted_tools={"get_iban", "get_balance", "get_user_info"},
    # Transactions are structured records: recipient/sender are fields written by
    # the bank, only the free-text `subject` is attacker-reachable. We parse the
    # YAML and read structured fields only (see state.py).
    record_tools={"get_most_recent_transactions", "get_scheduled_transactions"},
    self_value_tools={"get_iban": IBAN},
)

SLACK = SuitePolicy(
    name="slack",
    sinks={
        "invite_user_to_slack": {"user": _REF, "user_email": ArgSpec(IDENTITY, EMAIL)},
        "add_user_to_channel": {"user": _REF, "channel": _REF},
        "remove_user_from_slack": {"user": _REF},
        "send_direct_message": {"recipient": _REF, "body": _TXT},
        "send_channel_message": {"channel": _REF, "body": _TXT},
        "post_webpage": {"url": ArgSpec(IDENTITY, URL), "content": _TXT},
        "get_webpage": {"url": ArgSpec(IDENTITY, URL)},
    },
    trusted_tools={"get_channels", "get_users_in_channel"},
)

_EMAILS = ArgSpec(IDENTITY, EMAIL, is_list=True)
WORKSPACE = SuitePolicy(
    name="workspace",
    sinks={
        "send_email": {"recipients": _EMAILS, "cc": _EMAILS, "bcc": _EMAILS,
                       "subject": _TXT, "body": _TXT, "attachments": _TXT},
        "share_file": {"file_id": _REF, "email": ArgSpec(IDENTITY, EMAIL), "permission": _TXT},
        "create_calendar_event": {"participants": _EMAILS, "title": _TXT, "description": _TXT,
                                  "start_time": _TXT, "end_time": _TXT, "location": _TXT},
        "add_calendar_event_participants": {"event_id": _REF, "participants": _EMAILS},
        "delete_email": {"email_id": _REF},
        "delete_file": {"file_id": _REF},
    },
    trusted_tools={"get_current_day"},
)

TRAVEL = SuitePolicy(
    name="travel",
    sinks={
        "reserve_hotel": {"hotel": _REF, "start_day": _TXT, "end_day": _TXT},
        "reserve_car_rental": {"company": _REF, "start_time": _TXT, "end_time": _TXT},
        "reserve_restaurant": {"restaurant": _REF, "start_time": _TXT},
        "send_email": {"recipients": _EMAILS, "cc": _EMAILS, "bcc": _EMAILS,
                       "subject": _TXT, "body": _TXT, "attachments": _TXT},
        "create_calendar_event": {"participants": _EMAILS, "title": _TXT, "description": _TXT,
                                  "start_time": _TXT, "end_time": _TXT, "location": _TXT},
    },
    trusted_tools={"get_user_information"},
)

POLICIES: dict[str, SuitePolicy] = {p.name: p for p in (BANKING, SLACK, WORKSPACE, TRAVEL)}

# Tools that only exist in one suite, used to infer the suite from a catalog/trace.
_SUITE_MARKERS = {
    "banking": {"send_money", "get_iban", "get_most_recent_transactions"},
    "slack": {"invite_user_to_slack", "get_users_in_channel", "send_channel_message"},
    "workspace": {"search_calendar_events", "search_files_by_filename", "get_file_by_id"},
    "travel": {"reserve_hotel", "get_all_hotels_in_city", "reserve_car_rental"},
}


def infer_suite(tool_names) -> Optional[str]:
    names = set(tool_names or [])
    best, score = None, 0
    for suite, markers in _SUITE_MARKERS.items():
        s = len(names & markers)
        if s > score:
            best, score = suite, s
    return best


def get_policy(suite: Optional[str]) -> SuitePolicy:
    if suite not in POLICIES:
        raise KeyError(f"WITNESS has no policy for suite {suite!r}; known: {sorted(POLICIES)}")
    return POLICIES[suite]
