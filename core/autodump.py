"""
Shape normalisers for AutoDump JSON files.

WHY THIS EXISTS
---------------
`wow_jam_messages_<build>.json` was read by FOUR independent modules, each with
its own hardcoded list of category keys, and every one of those lists was
wrong:

    batch/importer.py          client_messages / server_messages / shared_structures
    analyzers/jam_recovery.py  client_messages / server_messages / shared_types
    analyzers/jam_metadata_apply.py   client_messages / server_messages / shared_structures
    analyzers/jam_type_discovery.py   client_messages / server_messages / shared_structures

AutoDump emits ``cmsg_messages`` / ``smsg_messages`` / ``both_messages`` /
``unk_messages``. None of the four lists matched, so all four silently
processed ZERO of the 482 message types on build 69382 — which took out JAM
recovery, wire-format recovery, packet codegen and opcode cross-linking
together, with no error anywhere.

One reader, one place to fix. Legacy key names are still accepted so older
dumps keep importing.
"""


#: (key in the JSON, implied direction or None) — current names first.
JAM_CATEGORIES = (
    ("cmsg_messages", "CMSG"),
    ("smsg_messages", "SMSG"),
    ("both_messages", None),
    ("unk_messages", None),
    # Legacy AutoDump layouts.
    ("client_messages", "CMSG"),
    ("server_messages", "SMSG"),
    ("shared_structures", None),
    ("shared_types", None),
)


def jam_categories_present(data):
    """Category keys that actually carry messages in *data*."""
    return [key for key, _direction in JAM_CATEGORIES if data.get(key)]


def iter_jam_messages(data):
    """Yield ``(message, category, implied_direction)`` for every JAM message.

    *implied_direction* is the direction the CATEGORY implies; a message's own
    ``direction`` field wins when present.
    """
    for key, implied in JAM_CATEGORIES:
        for message in data.get(key) or ():
            if isinstance(message, dict) and message.get("name"):
                yield message, key, implied


def jam_direction(message, implied=None):
    """Best-known direction for a message: CMSG, SMSG or None."""
    direction = (message.get("direction") or "").upper()
    if direction in ("CMSG", "SMSG"):
        return direction
    if direction == "BOTH":
        return None
    return implied


def jam_counts(data):
    """{category: count} for every category present — for reports/stats."""
    return {key: len(data.get(key) or ())
            for key, _d in JAM_CATEGORIES if data.get(key)}


#: Confidence words AutoDump uses, mapped to the 0-100 scale the DB stores.
CONFIDENCE_SCALE = {"high": 95, "med": 75, "medium": 75, "low": 50}


def confidence_value(message, default=60):
    """Numeric confidence for a JAM message."""
    return CONFIDENCE_SCALE.get((message.get("confidence") or "").lower(),
                                default)
