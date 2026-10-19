"""Version detection and v0.x -> v1.0 migration reporting.

The flagship day-one feature: the ecosystem is mid-migration (live cards were
still serving pre-1.0 shapes in Aug 2026), so this turns a card into a concrete
checklist instead of a vague "upgrade" suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .card import FetchInfo
from .spec import load_spec

OK = "ok"
ACTION = "action"
INFO = "info"


@dataclass
class MigrationItem:
    status: str   # ok | action | info
    check: str
    detail: str

    def __str__(self) -> str:
        mark = {"ok": "✓", "action": "✗", "info": "•"}[self.status]
        return f"[{mark}] {self.check}: {self.detail}"


def detect_card_version(card: Any) -> str:
    """Return '1.0', '0.x', or 'unknown' based on structural signals."""
    if not isinstance(card, dict):
        return "unknown"
    if isinstance(card.get("supportedInterfaces"), list):
        return "1.0"
    # v0.x signals: url + preferredTransport pair, or neither shape present
    if "url" in card or "preferredTransport" in card:
        return "0.x"
    return "unknown"


def _iface_protocol_versions(card: dict) -> list[Any]:
    out = []
    for iface in card.get("supportedInterfaces") or []:
        if isinstance(iface, dict):
            out.append(iface.get("protocolVersion"))
    return out


def compat_report(card: Any, fetch_info: Optional[FetchInfo] = None) -> list[MigrationItem]:
    """Build the migration report for a card."""
    spec = load_spec()
    items: list[MigrationItem] = []
    version = detect_card_version(card)

    # --- discovery path ------------------------------------------------
    if fetch_info is not None:
        if fetch_info.legacy_fallback:
            items.append(MigrationItem(
                ACTION, "discovery-path",
                f"card only resolved at legacy {fetch_info.path_used}; "
                f"v1.0 clients fetch {spec['card_path']}. Serve the v1.0 path (keep the old one as a redirect during migration)."))
        else:
            items.append(MigrationItem(OK, "discovery-path", f"card resolves at v1.0 path {fetch_info.path_used}"))
    else:
        items.append(MigrationItem(INFO, "discovery-path",
                                   f"card was supplied directly; v1.0 discovery path is {spec['card_path']}"))

    # --- interface shape -------------------------------------------------
    if version == "1.0":
        items.append(MigrationItem(OK, "supported-interfaces", "card uses v1.0 supportedInterfaces"))
        pvs = _iface_protocol_versions(card if isinstance(card, dict) else {})
        missing = [i for i, v in enumerate(pvs) if not v]
        if missing:
            items.append(MigrationItem(
                ACTION, "protocol-version",
                f"interface(s) {missing} lack protocolVersion; declare it (e.g. \"1.0\") so clients can negotiate"))
        else:
            items.append(MigrationItem(OK, "protocol-version", "every interface declares protocolVersion"))
        if isinstance(card, dict) and ("url" in card or "preferredTransport" in card):
            items.append(MigrationItem(
                ACTION, "legacy-fields",
                "card mixes v1.0 supportedInterfaces with legacy 'url'/'preferredTransport'; remove the legacy fields to avoid client confusion"))
    elif version == "0.x":
        items.append(MigrationItem(
            ACTION, "supported-interfaces",
            "card uses the pre-1.0 'url'/'preferredTransport' shape; migrate to 'supportedInterfaces' "
            "(ordered, first = preferred; each entry: url, protocolBinding, protocolVersion)"))
    else:
        items.append(MigrationItem(
            ACTION, "supported-interfaces",
            "could not detect the interface shape; a v1.0 card requires 'supportedInterfaces'"))

    # --- skill tags -------------------------------------------------------
    if isinstance(card, dict) and isinstance(card.get("skills"), list):
        untagged = [s.get("id", f"#{n}") for n, s in enumerate(card["skills"])
                    if isinstance(s, dict) and not s.get("tags")]
        if untagged:
            items.append(MigrationItem(
                ACTION, "skill-tags",
                f"skill(s) {untagged} lack 'tags' (mandatory since v1.0; routers match on them)"))
        else:
            items.append(MigrationItem(OK, "skill-tags", "every skill declares tags"))

    # --- state vocabulary (always informational: not visible on the card) --
    items.append(MigrationItem(
        INFO, "state-vocabulary",
        "wire task states are SCREAMING_SNAKE_CASE TASK_STATE_* in v1.0; normalize v0.x "
        "lowercase strings (submitted, input-required, ...) at the client edge. The v0.x "
        "'unknown' state was removed — treat TASK_STATE_UNSPECIFIED as a protocol violation."))

    # --- security model ----------------------------------------------------
    if isinstance(card, dict):
        schemes = card.get("securitySchemes")
        reqs = card.get("securityRequirements")
        if schemes and not reqs:
            items.append(MigrationItem(
                ACTION, "security-model",
                "securitySchemes are declared but securityRequirements is empty — nothing is actually required"))
        elif not schemes and reqs:
            items.append(MigrationItem(
                ACTION, "security-model",
                "securityRequirements references schemes, but securitySchemes is missing — clients cannot authenticate"))
        elif schemes and reqs:
            items.append(MigrationItem(OK, "security-model", "securitySchemes + securityRequirements both present"))
        else:
            items.append(MigrationItem(INFO, "security-model", "no auth declared; fine for public agents"))

    return items


def needs_migration(items: list[MigrationItem]) -> bool:
    return any(i.status == ACTION for i in items)


def format_report(items: list[MigrationItem]) -> str:
    return "\n".join(str(i) for i in items)
