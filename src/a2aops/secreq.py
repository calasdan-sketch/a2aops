"""Security-requirement parsing shared by validate, lint, auth, compat and diff.

A2A v1.0 (``a2a.proto``) defines::

    message StringList { repeated string list = 1; }
    message SecurityRequirement { map<string, StringList> schemes = 1; }

so the JSON wire form of ``AgentCard.securityRequirements`` (and
``AgentSkill.securityRequirements``) is::

    [{"schemes": {"oidc": {"list": ["bookings:write"]}}}]

Each array entry is one *alternative* (OR); the schemes inside an entry must
all be satisfied (AND). Pre-1.0 cards used the OpenAPI shape
``[{"oidc": ["bookings:write"]}]`` under ``security`` (v0.3) or
``securityRequirements``; that shape is accepted as a fallback and reported as
legacy so it can be migrated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

V1 = "v1"
LEGACY = "legacy"
INVALID = "invalid"


@dataclass
class Alternative:
    schemes: dict[str, list[str]]   # scheme name -> scopes
    shape: str                      # v1 | legacy | invalid
    index: int


def _scopes(value: Any) -> list[str]:
    if isinstance(value, dict):          # v1 StringList {"list": [...]}
        value = value.get("list", [])
    if isinstance(value, list):
        return [s for s in value if isinstance(s, str)]
    return []


def entry_shape(entry: Any) -> str:
    """Classify one requirement entry."""
    if not isinstance(entry, dict):
        return INVALID
    if set(entry) == {"schemes"} and isinstance(entry["schemes"], dict):
        return V1
    # A legacy entry maps scheme names straight to scope lists. A lone
    # "schemes" key whose value is a list is a legacy scheme literally named
    # "schemes", which is legal (if unwise).
    if all(isinstance(v, list) for v in entry.values()):
        return LEGACY
    return INVALID


def parse(entries: Any) -> list[Alternative]:
    """Parse a requirements array into alternatives (invalid entries kept, empty)."""
    out: list[Alternative] = []
    if not isinstance(entries, list):
        return out
    for n, entry in enumerate(entries):
        shape = entry_shape(entry)
        if shape == V1:
            schemes = {str(k): _scopes(v) for k, v in entry["schemes"].items()}
        elif shape == LEGACY:
            schemes = {str(k): _scopes(v) for k, v in entry.items()}
        else:
            schemes = {}
        out.append(Alternative(schemes, shape, n))
    return out


def requirements_field(obj: Any) -> Optional[str]:
    """Which field carries requirements: v1 ``securityRequirements`` or v0.3 ``security``."""
    if not isinstance(obj, dict):
        return None
    if "securityRequirements" in obj:
        return "securityRequirements"
    if "security" in obj:
        return "security"
    return None


def alternatives(obj: Any) -> list[Alternative]:
    field = requirements_field(obj)
    return parse(obj.get(field)) if field else []


def alternative_keys(obj: Any) -> set[frozenset[str]]:
    """Requirement alternatives as a set of scheme-name sets (scopes ignored)."""
    return {frozenset(a.schemes) for a in alternatives(obj) if a.shape != INVALID}


def referenced_schemes(card: Any) -> set[str]:
    """Every scheme name required anywhere: card level and skill level."""
    names: set[str] = set()
    if not isinstance(card, dict):
        return names
    for a in alternatives(card):
        names.update(a.schemes)
    skills = card.get("skills")
    if isinstance(skills, list):
        for s in skills:
            for a in alternatives(s):
                names.update(a.schemes)
    return names


def owners(card: Any) -> list[tuple[str, dict]]:
    """(path prefix, object) for the card and each skill that can carry requirements."""
    if not isinstance(card, dict):
        return []
    out: list[tuple[str, dict]] = [("", card)]
    skills = card.get("skills")
    if isinstance(skills, list):
        out += [(f"skills[{n}].", s) for n, s in enumerate(skills) if isinstance(s, dict)]
    return out
