"""Task-state normalization across A2A wire vocabularies.

A2A v1.0 uses SCREAMING_SNAKE_CASE TASK_STATE_* values on the wire. Pre-1.0
agents used lowercase strings (``submitted``, ``input-required``, ...) and had
an ``unknown`` state that no longer exists. This module normalizes both
vocabularies at the edge so the rest of the code works on one vocabulary.

Deliberately, this module does NOT encode a normative transition table: the
spec fixes the state set and the terminal set (and requires streams to close on
terminal states) but transitions beyond SUBMITTED -> WORKING are
implementation-defined. Only terminal immutability is enforced elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from .spec import load_spec

# Canonical classes
ACTIVE = "active"
INTERRUPTED = "interrupted"
TERMINAL = "terminal"
INVALID = "invalid"


@dataclass(frozen=True)
class NormalizedState:
    """A task state normalized to the v1.0 vocabulary."""

    name: str          # canonical v1 name, e.g. "WORKING"; "UNKNOWN" if unmapped
    vocabulary: str    # "v1" | "v0" | "unknown"
    known: bool        # False when the raw string matched nothing
    terminal: bool     # True for the four terminal states


def normalize_state(raw: object) -> NormalizedState:
    """Normalize any wire state string to the v1.0 vocabulary.

    Accepts "TASK_STATE_WORKING", "WORKING", "working", "input-required", etc.
    The v0.x "unknown" state maps to UNSPECIFIED-adjacent handling: it is
    reported as known-but-removed so callers can flag the drift.
    """
    spec = load_spec()
    v1 = spec["task_states_v1"]
    v0 = spec["task_states_v0"]
    terminal = set(spec["terminal_states"])

    if not isinstance(raw, str) or not raw.strip():
        return NormalizedState("UNSPECIFIED", "unknown", False, False)

    s = raw.strip()

    def v1_lookup(key: str) -> NormalizedState | None:
        if key in v1:
            short = key[len("TASK_STATE_"):]
            return NormalizedState(short, "v1", True, v1[key]["class"] == "terminal")
        return None

    # 1. exact v1 wire form
    hit = v1_lookup(s)
    if hit:
        return hit

    # 2. v0 lowercase vocabulary ("submitted", "input-required", "unknown").
    #    Only exact-lowercase raw strings attribute to v0; anything else
    #    falls through to the case-insensitive v1 lookup below.
    low = s.lower()
    if s == low and low in v0:
        mapped = v0[low]
        if mapped is None:
            # v0 "unknown": removed in v1.0; surfaced explicitly, not silently.
            return NormalizedState("UNKNOWN", "v0", True, True)
        short = mapped[len("TASK_STATE_"):]
        return NormalizedState(short, "v0", True, short in terminal)

    # 3. bare v1 name in any case ("WORKING", "working")
    hit = v1_lookup(f"TASK_STATE_{s.upper().replace('-', '_')}")
    if hit:
        return hit

    return NormalizedState("UNSPECIFIED", "unknown", False, False)


def state_class(name: str) -> str:
    """Return the class (active/interrupted/terminal/invalid) of a canonical state."""
    spec = load_spec()
    v1 = spec["task_states_v1"]
    key = f"TASK_STATE_{name}"
    if key not in v1:
        return INVALID
    return v1[key]["class"]


def is_terminal(name: str) -> bool:
    return state_class(name) == TERMINAL
