"""
Offline tests for the pure logic of analyzers/opcode_dispatch_switch.py.

The IDA-dependent part (get_switch_info / calc_switch_cases enumeration) can only
run inside IDA, but the family-binding oracle — the part that decides whether a
decoded switch is an opcode dispatcher and which family it belongs to — is pure
and is the part that can fabricate opcodes if it is wrong. These tests pin its
behaviour: authoritative code hints resolve the family, and ambiguous switches
(low indices shared by many families, struct-copy switches) are rejected rather
than guessed.

Run: python tests/test_opcode_dispatch_switch.py
"""

import os
import sys
import types
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "..", "analyzers", "opcode_dispatch_switch.py")


def _load_module():
    """Load the analyzer with its tc_wow_analyzer.* deps stubbed (no IDA)."""
    pkg = types.ModuleType("tc_wow_analyzer"); pkg.__path__ = []
    core = types.ModuleType("tc_wow_analyzer.core"); core.__path__ = []
    utils = types.ModuleType("tc_wow_analyzer.core.utils")
    for n in ("msg_info", "msg_warn", "msg_error"):
        setattr(utils, n, lambda *a, **k: None)
    utils.dumps_dir = lambda: "/tmp"
    utils.dumps_build_path = lambda *a, **k: "/nonexistent"
    utils.current_build = lambda: 69382
    kvk = types.ModuleType("tc_wow_analyzer.core.kv_keys")
    kvk.OPCODE_DISPATCH_SWITCH = "opcode_dispatch_switch"
    sys.modules.update({
        "tc_wow_analyzer": pkg,
        "tc_wow_analyzer.core": core,
        "tc_wow_analyzer.core.utils": utils,
        "tc_wow_analyzer.core.kv_keys": kvk,
    })
    spec = importlib.util.spec_from_file_location("ods_under_test", MOD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synthetic_oracle():
    """Two families with overlapping low indices, like the real catalog.

    HOUSE base 0x420000 has indices {0..5, 0x100, 0x101, 0x200}.
    GUILD base 0x4E0000 has indices {0..5, 0x40, 0x41}.
    Indices 0..5 are shared, so a switch over {0..5} is genuinely ambiguous.
    """
    union = {}
    for i in list(range(6)) + [0x100, 0x101, 0x200]:
        union["CMSG_HOUSE_%X" % i] = {"value": "0x%X" % (0x420000 + i),
                                      "direction": "CMSG"}
    for i in list(range(6)) + [0x40, 0x41]:
        union["SMSG_GUILD_%X" % i] = {"value": "0x%X" % (0x4E0000 + i),
                                      "direction": "SMSG"}
    return union


def run():
    ods = _load_module()
    known, bases = ods.build_oracle_from_union(_synthetic_oracle())
    assert (0x420000 + 0x200) in known
    assert 0x420000 in bases and 0x4E0000 in bases and 0 in bases

    HOUSE, GUILD = 0x420000, 0x4E0000
    house_idx = [0, 1, 2, 3, 4, 5, 0x100, 0x101, 0x200]
    checks = []

    def ck(label, cond):
        checks.append((label, bool(cond)))

    # 1. PRIMARY path: IDA reports the real opcode values as case labels
    #    (base folded into lowcase). base 0 matches directly.
    b, m = ods.bind_family([HOUSE + i for i in house_idx], known, bases)
    ck("full-opcode case labels bind to base 0", b == 0 and len(m) == len(house_idx))

    # 2. An unrelated switch(state) has small-int labels 0..5 that are not
    #    opcodes at base 0 and there is no code hint -> rejected (no fabrication).
    b, m = ods.bind_family([0, 1, 2, 3, 4, 5], known, bases)
    ck("raw small-int labels rejected without hint", b is None)

    # 3. A large dense unrelated switch (0..0x200) must NOT be captured by the
    #    densest family without a code hint. base 0 sees no opcodes here.
    b, m = ods.bind_family(house_idx, known, bases)
    ck("dense non-opcode switch not captured without hint", b is None)

    # 4. Index-form dispatcher WITH its own base immediate -> family base used.
    b, m = ods.bind_family([0, 1, 2, 3, 4, 5], known, bases, base_hints={GUILD})
    ck("code hint enables index-form binding", b == GUILD and len(m) == 6)

    # 5. Multi-hint function (two family immediates) -> best-matching wins.
    b, m = ods.bind_family(house_idx, known, bases, base_hints={HOUSE, GUILD})
    ck("multi-hint picks best-matching family", b == HOUSE)

    # 6. Junk case values are excluded from the matched set (base 0 path).
    full = [HOUSE + i for i in house_idx] + [0x999999]
    b, m = ods.bind_family(full, known, bases)
    ck("junk case value excluded", b == 0 and 0x999999 not in m)

    # 7. A tiny switch below the minimum is rejected even at base 0.
    b, m = ods.bind_family([HOUSE + 0, HOUSE + 1], known, bases)
    ck("tiny switch rejected", b is None)

    # --- JAM type-name remap: the build-shift-proof family identification ---
    # Real 69382 evidence: the client's own WowGetRawTypeName<> strings.
    ck("name_tokens drops generic words",
       ods.name_tokens("SMSG_SETUP_CURRENCY") == {"SETUP", "CURRENCY"})
    ck("type_tokens strips Jam/Client prefix",
       {"SETUP", "CURRENCY"} <= ods.type_tokens(["ClientSetupCurrencyRecord"]))

    # A client family whose handlers reference currency/achievement/mail types
    # must resolve to HOUSE-base only if the NAMES agree. Build a catalog where
    # family 0x42 holds those names and 0x3A holds unrelated ones.
    kv = {}
    real = {0x00: ("SMSG_SETUP_CURRENCY", "SMSG"),
            0x01: ("SMSG_ALL_ACHIEVEMENT_DATA", "SMSG"),
            0x02: ("SMSG_REGIONWIDE_CHARACTER_MAIL_DATA", "SMSG"),
            0x03: ("SMSG_RAID_MARKERS_CHANGED", "SMSG"),
            0x04: ("SMSG_TRANSMOG_OUTFIT_SLOTS_UPDATED", "SMSG"),
            0x05: ("SMSG_UPDATE_TALENT_DATA", "SMSG"),
            0x06: ("SMSG_MOUNT_RESULT", "SMSG"),
            0x07: ("SMSG_PET_MODE", "SMSG"),
            0x08: ("SMSG_TRADE_STATUS", "SMSG"),
            0x09: ("SMSG_BIND_POINT_UPDATE", "SMSG")}
    decoy = {i: ("SMSG_GUILD_ROSTER_%d" % i, "SMSG") for i in range(10)}
    for i, v in real.items():
        kv[(0x42 << 16) | i] = v
    for i, v in decoy.items():
        kv[(0x3A << 16) | i] = v
    idx_types = {
        0x00: ["ClientSetupCurrencyRecord"],
        0x01: ["JamEarnedAchievement", "JamCriteriaProgress"],
        0x02: ["RegionwideCharacterMail"],
        0x03: ["JamCliRaidMarkerData"],
        0x04: ["JamTransmogOutfitSituationInfo"],
        0x05: ["JamPvPTalent"],
        0x06: ["JamClientAccountMount"],
        0x07: ["JamPetBattleFinalPet"],
        0x08: ["JamTradeStatusInfo"],
        0x09: ["JamBindPointInfo"],
    }
    hits42, tested42 = ods.score_client_family(idx_types, kv, 0x42)
    hits3a, tested3a = ods.score_client_family(idx_types, kv, 0x3A)
    ck("type names match the true family", hits42 >= 8 and tested42 == 10)
    ck("type names do NOT match a wrong family", hits3a == 0)

    pick = ods.choose_catalog_family(idx_types, kv, [0x42, 0x3A])
    ck("correct catalog family chosen", pick and pick["family"] == 0x42)

    # Ambiguity guard: if no family separates, refuse rather than guess.
    flat = {i: ["JamThing"] for i in range(10)}
    ck("ambiguous type names rejected",
       ods.choose_catalog_family(flat, kv, [0x42, 0x3A]) is None)

    # DIRECTION FILTER: the CMSG twin of a subsystem must NOT win.
    # Real 69382 failure: client 0x4A (JamWhoEntry/JamClientMOTDStruct) scored
    # CMSG_CHAT_* over the correct SMSG_WHO/SMSG_MOTD until SMSG-only scoring.
    kv2 = {}
    smsg_names = {0x02: ("SMSG_WHO", "SMSG"), 0x03: ("SMSG_MOTD", "SMSG"),
                  0x05: ("SMSG_EXPECTED_SPAM_RECORDS", "SMSG"),
                  0x08: ("SMSG_CAUTIONARY_CHAT_MESSAGE", "SMSG"),
                  0x09: ("SMSG_CAUTIONARY_CHANNEL_MESSAGE", "SMSG")}
    cmsg_names = {i: ("CMSG_CHAT_THING_%d" % i, "CMSG") for i in range(0x20)}
    for i, v in smsg_names.items():
        kv2[(0x47 << 16) | i] = v
    for i, v in cmsg_names.items():
        kv2[(0x2B << 16) | i] = v
    who = {0x02: ["JamWhoEntry"], 0x03: ["JamClientMOTDStruct"],
           0x05: ["JamClientSpamRecord"], 0x08: ["JamChatMessage"],
           0x09: ["JamChatChannelMessage"]}
    h47, _ = ods.score_client_family(who, kv2, 0x47)
    h2b, t2b = ods.score_client_family(who, kv2, 0x2B)
    ck("SMSG family scores on real evidence", h47 >= 3)
    ck("CMSG twin is filtered out entirely", t2b == 0 and h2b == 0)
    pick2 = ods.choose_catalog_family(who, kv2, [0x47, 0x2B])
    ck("direction filter picks the SMSG family", pick2 and pick2["family"] == 0x47)

    # Too little evidence -> refuse (min_tested guard).
    ck("insufficient evidence rejected",
       ods.choose_catalog_family({0x00: ["ClientSetupCurrencyRecord"],
                                  0x01: ["JamEarnedAchievement"]},
                                 kv, [0x42, 0x3A]) is None)

    ok = all(p for _, p in checks)
    for label, p in checks:
        print(("[ OK ]" if p else "[FAIL]"), label)
    print("\n%s" % ("All opcode_dispatch_switch tests passed."
                    if ok else "SOME TESTS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
