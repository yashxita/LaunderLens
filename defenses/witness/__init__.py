"""
WITNESS — nonmalleable endorsement of delegated values (Direction A).

    from witness import Witness, make_witness, CONFIGS

See design/DEFENSE_DESIGN.md for the design and RUN_WITNESS.md for how to run it.
"""

from .gate import (CONFIGS, Witness, WitnessConfig, make_witness,
                   READ, UNCHECKED, ENDORSED_USER, ENDORSED_TRUSTED, ENDORSED_PRESENT,
                   ENDORSED_UNIQUE, ENDORSED_CORROBORATED, ENDORSED_CONFIRMED, ENDORSED_ANY,
                   BLOCKED_CONTROL, BLOCKED_UNSUPPORTED, BLOCKED_CONFLICT, BLOCKED_USER, ESCALATED)
from .confirm import ABSTAIN, ORACLE
from .state import load_seed

__all__ = [
    "Witness", "WitnessConfig", "CONFIGS", "make_witness", "load_seed", "ABSTAIN", "ORACLE",
    "READ", "UNCHECKED", "ENDORSED_USER", "ENDORSED_TRUSTED", "ENDORSED_PRESENT",
    "ENDORSED_UNIQUE", "ENDORSED_CORROBORATED", "ENDORSED_CONFIRMED", "ENDORSED_ANY",
    "BLOCKED_CONTROL", "BLOCKED_UNSUPPORTED", "BLOCKED_CONFLICT", "BLOCKED_USER", "ESCALATED",
]
