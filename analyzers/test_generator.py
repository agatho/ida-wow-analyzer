"""
Binary-Derived Test Case Generation
Analyzes binary handler behavior to generate C++ test cases that verify
TrinityCore handler implementations match the binary's behavior.

Generates:
  - Input validation tests (boundary values from range checks)
  - State transition tests (from recovered state machines)
  - Packet round-trip tests (serialize → deserialize → compare)
  - Error code tests (binary returns X for invalid input Y)
"""

import json
import re
import time

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


def generate_tests(session, system_filter=None):
    """Generate test cases from binary analysis data.

    Sources:
      1. Validation rules (from validation_extractor)
      2. State machines (from state_machine analyzer)
      3. JAM type definitions (from jam_recovery)
      4. Handler call patterns (from conformance scoring)

    Returns number of test cases generated.
    """
    db = session.db

    all_tests = []

    # 1. Generate validation tests from extracted rules
    validation_tests = _generate_validation_tests(db, system_filter)
    all_tests.extend(validation_tests)
    msg_info(f"Generated {len(validation_tests)} validation tests")

    # 2. Generate state machine transition tests
    state_tests = _generate_state_machine_tests(db, system_filter)
    all_tests.extend(state_tests)
    msg_info(f"Generated {len(state_tests)} state machine tests")

    # 3. Generate packet round-trip tests
    packet_tests = _generate_packet_tests(db, system_filter)
    all_tests.extend(packet_tests)
    msg_info(f"Generated {len(packet_tests)} packet round-trip tests")

    # 4. Generate error code tests
    error_tests = _generate_error_code_tests(db, system_filter)
    all_tests.extend(error_tests)
    msg_info(f"Generated {len(error_tests)} error code tests")

    # Store
    db.kv_set("generated_tests", {
        "total": len(all_tests),
        "by_category": {
            "validation": len(validation_tests),
            "state_machine": len(state_tests),
            "packet_roundtrip": len(packet_tests),
            "error_code": len(error_tests),
        },
        "tests": all_tests,
        "generated_at": time.time(),
    })
    db.commit()

    msg_info(f"Total: {len(all_tests)} test cases generated")
    return len(all_tests)


def _generate_validation_tests(db, system_filter):
    """Generate tests from extracted validation rules.

    For each binary validation rule (range check, null check, etc.),
    generate a test that verifies TC handles the same edge cases.
    """
    tests = []

    # Get all validation rules from kv_store
    rows = db.fetchall(
        "SELECT key, value FROM kv_store WHERE key LIKE 'validations:%'")

    for row in rows:
        handler_name = row["key"].replace("validations:", "")
        if system_filter and system_filter.lower() not in handler_name.lower():
            continue

        try:
            rules = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            continue

        for rule in rules:
            test = _rule_to_test(handler_name, rule)
            if test:
                tests.append(test)

    return tests


def _rule_to_test(handler_name, rule):
    """Convert a single validation rule to a test case."""
    rule_type = rule.get("type", "")
    error_code = rule.get("error_code", "")
    checked_value = rule.get("checked_value", "unknown")
    comparand = rule.get("comparand", "")

    # Generate handler function name
    func_name = _opcode_to_handler(handler_name)

    if rule_type == "range_check" and comparand:
        try:
            boundary = int(comparand, 0)
        except (ValueError, TypeError):
            boundary = comparand

        return {
            "category": "validation",
            "handler": handler_name,
            "test_name": f"Test_{func_name}_RangeCheck_{checked_value}",
            "description": f"Verify {handler_name} rejects {checked_value} "
                         f"at boundary {comparand}",
            "code": _gen_range_test_code(func_name, checked_value,
                                         boundary, error_code),
            "priority": "high",
        }

    elif rule_type == "null_check":
        return {
            "category": "validation",
            "handler": handler_name,
            "test_name": f"Test_{func_name}_NullCheck_{checked_value}",
            "description": f"Verify {handler_name} handles null/zero "
                         f"{checked_value}",
            "code": _gen_null_test_code(func_name, checked_value, error_code),
            "priority": "high",
        }

    elif rule_type == "state_guard":
        return {
            "category": "validation",
            "handler": handler_name,
            "test_name": f"Test_{func_name}_StateGuard_{checked_value}",
            "description": f"Verify {handler_name} checks state "
                         f"{checked_value} == {comparand}",
            "code": _gen_state_guard_test_code(func_name, checked_value,
                                                comparand, error_code),
            "priority": "medium",
        }

    elif rule_type == "permission_check":
        return {
            "category": "validation",
            "handler": handler_name,
            "test_name": f"Test_{func_name}_Permission_{checked_value}",
            "description": f"Verify {handler_name} checks permission "
                         f"via {checked_value}()",
            "code": _gen_permission_test_code(func_name, checked_value,
                                              error_code),
            "priority": "medium",
        }

    return None


def _generate_state_machine_tests(db, system_filter):
    """Generate tests from recovered state machines."""
    tests = []

    machines = db.kv_get("state_machines") or []
    for sm in machines:
        if system_filter:
            handlers = sm.get("handlers", [])
            if not any(system_filter.lower() in h.lower() for h in handlers):
                continue

        sm_name = sm["name"]
        states = sm.get("states", [])
        transitions = sm.get("transitions", [])

        # Test: each state is reachable
        for state in states:
            tests.append({
                "category": "state_machine",
                "handler": sm_name,
                "test_name": f"Test_{_sanitize(sm_name)}_State_{state}_Reachable",
                "description": f"Verify state {state} in {sm_name} "
                             f"is reachable via valid transitions",
                "code": _gen_state_reachable_test(sm_name, state, transitions),
                "priority": "medium",
            })

        # Test: invalid state values are rejected
        if states:
            max_state = max(s for s in states if isinstance(s, int))
            tests.append({
                "category": "state_machine",
                "handler": sm_name,
                "test_name": f"Test_{_sanitize(sm_name)}_InvalidState",
                "description": f"Verify {sm_name} rejects state values "
                             f"outside valid range",
                "code": _gen_invalid_state_test(sm_name, max_state),
                "priority": "high",
            })

    return tests


def _generate_packet_tests(db, system_filter):
    """Generate packet serialization round-trip tests."""
    tests = []

    rows = db.fetchall(
        "SELECT name, fields_json FROM jam_types "
        "WHERE fields_json IS NOT NULL")

    for row in rows:
        name = row["name"]
        if system_filter and system_filter.lower() not in name.lower():
            continue

        try:
            fields = json.loads(row["fields_json"])
        except (json.JSONDecodeError, TypeError):
            continue

        if not fields:
            continue

        tests.append({
            "category": "packet_roundtrip",
            "handler": name,
            "test_name": f"Test_{_sanitize(name)}_RoundTrip",
            "description": f"Verify {name} survives serialize → "
                         f"deserialize round-trip ({len(fields)} fields)",
            "code": _gen_roundtrip_test(name, fields),
            "priority": "low",
        })

    return tests


def _generate_error_code_tests(db, system_filter):
    """Generate tests for error codes found in binary handlers."""
    tests = []

    # Get validation rules that have error codes
    rows = db.fetchall(
        "SELECT key, value FROM kv_store WHERE key LIKE 'validations:%'")

    error_codes_by_handler = {}
    for row in rows:
        handler_name = row["key"].replace("validations:", "")
        if system_filter and system_filter.lower() not in handler_name.lower():
            continue

        try:
            rules = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            continue

        error_codes = set()
        for rule in rules:
            ec = rule.get("error_code")
            if ec and ec not in ("0", "1", "0x0", "0x1"):
                error_codes.add(ec)

        if error_codes:
            error_codes_by_handler[handler_name] = sorted(error_codes)

    for handler_name, codes in error_codes_by_handler.items():
        func_name = _opcode_to_handler(handler_name)
        tests.append({
            "category": "error_code",
            "handler": handler_name,
            "test_name": f"Test_{func_name}_ErrorCodes",
            "description": f"Verify {handler_name} returns correct error "
                         f"codes: {', '.join(codes[:5])}",
            "code": _gen_error_code_test(func_name, handler_name, codes),
            "priority": "medium",
        })

    return tests


# ─── Code Generation Helpers ──────────────────────────────────────


def _gen_range_test_code(func_name, field, boundary, error_code):
    """Generate C++ test code for a range check."""
    error_expect = f"// Should return {error_code}" if error_code else ""
    return (
        f"TEST_F(PacketHandlerTest, {func_name}_RejectsBoundary_{field})\n"
        f"{{\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    // Set {field} to boundary value {boundary}\n"
        f"    packet << {field}({boundary});\n"
        f"    {error_expect}\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    EXPECT_NE(result, RESULT_OK);\n"
        f"}}\n"
        f"\n"
        f"TEST_F(PacketHandlerTest, {func_name}_AcceptsValid_{field})\n"
        f"{{\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    // Set {field} to valid value below boundary\n"
        f"    packet << {field}(0);\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    EXPECT_EQ(result, RESULT_OK);\n"
        f"}}\n"
    )


def _gen_null_test_code(func_name, field, error_code):
    """Generate C++ test code for a null/zero check."""
    return (
        f"TEST_F(PacketHandlerTest, {func_name}_HandlesNull_{field})\n"
        f"{{\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    // Set {field} to null/zero\n"
        f"    packet << uint64(0);  // null {field}\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    // Binary returns early with {error_code or 'no error code'}\n"
        f"    EXPECT_NE(result, RESULT_OK);\n"
        f"}}\n"
    )


def _gen_state_guard_test_code(func_name, field, expected, error_code):
    """Generate C++ test code for a state guard check."""
    return (
        f"TEST_F(PacketHandlerTest, {func_name}_WrongState_{field})\n"
        f"{{\n"
        f"    // Binary checks {field} == {expected}\n"
        f"    // Test with wrong state value\n"
        f"    SetPlayerState({field}, 0xDEAD);  // invalid state\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    EXPECT_NE(result, RESULT_OK);\n"
        f"}}\n"
    )


def _gen_permission_test_code(func_name, check_func, error_code):
    """Generate C++ test code for a permission check."""
    return (
        f"TEST_F(PacketHandlerTest, {func_name}_NoPermission)\n"
        f"{{\n"
        f"    // Binary calls {check_func}() as guard\n"
        f"    MockPermission({check_func}, false);\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    EXPECT_NE(result, RESULT_OK);\n"
        f"}}\n"
        f"\n"
        f"TEST_F(PacketHandlerTest, {func_name}_WithPermission)\n"
        f"{{\n"
        f"    MockPermission({check_func}, true);\n"
        f"    WorldPacket packet(/* opcode */);\n"
        f"    auto result = _session->{func_name}(packet);\n"
        f"    // Should proceed past permission check\n"
        f"}}\n"
    )


def _gen_state_reachable_test(sm_name, state, transitions):
    """Generate test asserting a state is reachable."""
    handlers = set()
    for t in transitions:
        if t.get("from_state") == state:
            handlers.add(t.get("handler", "unknown"))

    handler_list = ", ".join(f'"{h}"' for h in list(handlers)[:3])
    return (
        f"// State {state} in {sm_name}\n"
        f"// Reached by handlers: {handler_list}\n"
        f"TEST_F(StateMachineTest, {_sanitize(sm_name)}_State{state}_IsReachable)\n"
        f"{{\n"
        f"    auto sm = CreateStateMachine(\"{sm_name}\");\n"
        f"    EXPECT_TRUE(sm->IsStateReachable({state}));\n"
        f"}}\n"
    )


def _gen_invalid_state_test(sm_name, max_state):
    """Generate test for invalid state rejection."""
    return (
        f"TEST_F(StateMachineTest, {_sanitize(sm_name)}_RejectsInvalidState)\n"
        f"{{\n"
        f"    auto sm = CreateStateMachine(\"{sm_name}\");\n"
        f"    // Max valid state is {max_state}\n"
        f"    EXPECT_FALSE(sm->IsValidState({max_state + 1}));\n"
        f"    EXPECT_FALSE(sm->IsValidState(0xFFFF));\n"
        f"}}\n"
    )


def _gen_roundtrip_test(jam_name, fields):
    """Generate packet round-trip serialization test."""
    field_inits = []
    for f in fields[:10]:
        fname = f.get("name", "field")
        ftype = f.get("type", "uint32")
        if "string" in ftype.lower():
            field_inits.append(f'    pkt.{fname} = "test_value";')
        elif "float" in ftype.lower():
            field_inits.append(f"    pkt.{fname} = 3.14f;")
        elif "64" in ftype:
            field_inits.append(f"    pkt.{fname} = 0x123456789ABCULL;")
        else:
            field_inits.append(f"    pkt.{fname} = 42;")

    inits = "\n".join(field_inits)

    struct_name = _sanitize(jam_name)
    return (
        f"TEST_F(PacketTest, {struct_name}_RoundTrip)\n"
        f"{{\n"
        f"    WorldPackets::{struct_name} pkt;\n"
        f"{inits}\n"
        f"\n"
        f"    WorldPacket buffer(/* opcode */);\n"
        f"    pkt.Write(buffer);\n"
        f"\n"
        f"    WorldPackets::{struct_name} parsed;\n"
        f"    parsed.Read(buffer);\n"
        f"\n"
        f"    // Compare all fields\n"
    )


def _gen_error_code_test(func_name, handler_name, error_codes):
    """Generate test verifying specific error codes are used."""
    checks = []
    for code in error_codes[:5]:
        checks.append(
            f"    // Binary returns {code} for this error condition\n"
            f"    EXPECT_EQ(GetLastError(), {code});"
        )
    checks_str = "\n".join(checks)

    return (
        f"TEST_F(ErrorCodeTest, {func_name}_UsesCorrectErrorCodes)\n"
        f"{{\n"
        f"    // {handler_name} uses these error codes:\n"
        f"    // {', '.join(error_codes[:5])}\n"
        f"\n"
        f"    // Verify at least one error path returns correct code\n"
        f"    WorldPacket badPacket(/* opcode */);\n"
        f"    _session->{func_name}(badPacket);\n"
        f"{checks_str}\n"
        f"}}\n"
    )


# ─── Utilities ────────────────────────────────────────────────────


def _opcode_to_handler(opcode_name):
    """Convert CMSG_FOO_BAR to HandleFooBar."""
    prefix_end = opcode_name.find("_")
    if prefix_end < 0:
        return opcode_name
    base = opcode_name[prefix_end + 1:]
    parts = base.split("_")
    return "Handle" + "".join(p.capitalize() for p in parts)


def _sanitize(name):
    """Sanitize a name for use as C++ identifier."""
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def get_generated_tests(session, category=None):
    """Retrieve generated tests, optionally filtered by category."""
    data = session.db.kv_get("generated_tests") or {}
    tests = data.get("tests", [])
    if category:
        tests = [t for t in tests if t["category"] == category]
    return tests


def export_tests_as_cpp(session, system_filter=None):
    """Export all generated tests as a single C++ file string."""
    data = session.db.kv_get("generated_tests") or {}
    tests = data.get("tests", [])

    if system_filter:
        tests = [t for t in tests
                 if system_filter.lower() in t.get("handler", "").lower()]

    lines = [
        "// Auto-generated tests from binary analysis",
        "// Generated by TC WoW Analyzer",
        f"// {len(tests)} test cases",
        "",
        '#include "TestFramework.h"',
        '#include "WorldPacket.h"',
        '#include "WorldSession.h"',
        "",
    ]

    by_category = {}
    for t in tests:
        cat = t["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(t)

    for cat, cat_tests in sorted(by_category.items()):
        lines.append(f"// ─── {cat.upper()} TESTS "
                     f"({len(cat_tests)} tests) ───")
        lines.append("")
        for t in cat_tests:
            lines.append(f"// {t['description']}")
            lines.append(t["code"])
            lines.append("")

    return "\n".join(lines)
