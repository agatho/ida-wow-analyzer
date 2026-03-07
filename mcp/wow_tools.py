"""
WoW-Specific MCP Tools
Extends the ida-pro-mcp server with 16 domain-specific tools for
WoW binary analysis. These tools are exposed via JSON-RPC to Claude Code
and other MCP clients.

Tool categories:
  - Opcode lookup & handler navigation
  - JAM wire format inspection
  - DB2 metadata queries
  - VTable/class hierarchy browsing
  - Housing system exploration
  - Function classification & search
  - Cross-reference analysis
"""

import json


def register_wow_tools(session):
    """Register all WoW-specific MCP tools with the MCP server.

    This hooks into the existing ida-pro-mcp server running on port 13337
    by registering additional tool handlers.
    """
    tools = WoWMCPTools(session)
    return tools


class WoWMCPTools:
    """Collection of WoW-specific MCP tools backed by the knowledge DB."""

    def __init__(self, session):
        self._session = session
        self._tools = self._build_tool_registry()

    def _build_tool_registry(self):
        """Build the registry of available tools."""
        return {
            "wow_lookup_opcode": {
                "description": "Look up a WoW opcode by name, index, or handler address",
                "handler": self.tool_lookup_opcode,
                "params": {
                    "query": "Opcode name, hex index (0x420127), or handler address",
                    "direction": "Optional: CMSG or SMSG (default: both)",
                },
            },
            "wow_get_wire_format": {
                "description": "Get the JAM wire format (field layout) for a message type",
                "handler": self.tool_get_wire_format,
                "params": {
                    "jam_name": "JAM type name (e.g. JamCliHouseDecorAction)",
                },
            },
            "wow_list_jam_types": {
                "description": "List all known JAM message types, optionally filtered",
                "handler": self.tool_list_jam_types,
                "params": {
                    "filter": "Optional substring filter (e.g. 'House', 'Neighborhood')",
                    "limit": "Max results (default 50)",
                },
            },
            "wow_lookup_db2": {
                "description": "Look up DB2 table metadata by name",
                "handler": self.tool_lookup_db2,
                "params": {
                    "name": "DB2 table name (e.g. HouseDecorItem, Neighborhood)",
                },
            },
            "wow_list_db2_tables": {
                "description": "List DB2 tables, optionally filtered by name",
                "handler": self.tool_list_db2_tables,
                "params": {
                    "filter": "Optional substring filter",
                    "limit": "Max results (default 50)",
                },
            },
            "wow_get_vtable": {
                "description": "Get vtable entries for a class",
                "handler": self.tool_get_vtable,
                "params": {
                    "class_name": "Class name (e.g. CGHousing_C, Neighborhood)",
                },
            },
            "wow_get_class_hierarchy": {
                "description": "Get class inheritance hierarchy",
                "handler": self.tool_get_class_hierarchy,
                "params": {
                    "class_name": "Class name to trace hierarchy for",
                },
            },
            "wow_search_functions": {
                "description": "Search functions by name pattern or system",
                "handler": self.tool_search_functions,
                "params": {
                    "query": "Name pattern (supports % wildcards)",
                    "system": "Optional: filter by system (housing, combat, etc.)",
                    "limit": "Max results (default 50)",
                },
            },
            "wow_classify_function": {
                "description": "Classify a function into a game system",
                "handler": self.tool_classify_function,
                "params": {
                    "address": "Function address (hex)",
                    "system": "System name (housing, combat, quest, etc.)",
                    "subsystem": "Optional subsystem name",
                },
            },
            "wow_get_housing_overview": {
                "description": "Get complete housing system overview (opcodes, JAM types, functions, DB2 tables)",
                "handler": self.tool_get_housing_overview,
                "params": {},
            },
            "wow_get_opcode_handler_chain": {
                "description": "Trace an opcode from dispatch to handler to JAM deserializer",
                "handler": self.tool_get_opcode_handler_chain,
                "params": {
                    "opcode_name": "TrinityCore opcode name or internal index",
                },
            },
            "wow_get_update_fields": {
                "description": "Get update fields for an object type",
                "handler": self.tool_get_update_fields,
                "params": {
                    "object_type": "Object type (OBJECT, ITEM, UNIT, PLAYER, GAMEOBJECT, etc.)",
                },
            },
            "wow_get_lua_api": {
                "description": "Look up Lua API functions",
                "handler": self.tool_get_lua_api,
                "params": {
                    "query": "Function name or namespace (supports % wildcards)",
                },
            },
            "wow_get_db_stats": {
                "description": "Get knowledge database statistics",
                "handler": self.tool_get_db_stats,
                "params": {},
            },
            "wow_annotate_function": {
                "description": "Add a knowledge annotation to a function",
                "handler": self.tool_annotate_function,
                "params": {
                    "address": "Function address (hex)",
                    "annotation_type": "Type: comment, system_label, type",
                    "value": "Annotation value",
                },
            },
            "wow_cross_reference": {
                "description": "Find cross-references between game systems at an address",
                "handler": self.tool_cross_reference,
                "params": {
                    "address": "Address to analyze (hex)",
                },
            },
        }

    def get_tool_definitions(self):
        """Return tool definitions in MCP format."""
        return [
            {
                "name": name,
                "description": info["description"],
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        k: {"type": "string", "description": v}
                        for k, v in info["params"].items()
                    },
                },
            }
            for name, info in self._tools.items()
        ]

    def handle_tool_call(self, tool_name, arguments):
        """Handle an MCP tool call."""
        tool = self._tools.get(tool_name)
        if not tool:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return tool["handler"](arguments)
        except Exception as e:
            return {"error": str(e)}

    # ─── Tool Implementations ─────────────────────────────────────

    def tool_lookup_opcode(self, args):
        db = self._session.db
        query = args.get("query", "")
        direction = args.get("direction")

        results = []

        # Try as hex index
        if query.startswith("0x"):
            try:
                idx = int(query, 16)
                rows = db.fetchall(
                    "SELECT * FROM opcodes WHERE internal_index = ?", (idx,))
                results.extend(rows)
            except ValueError:
                pass

        # Try as name
        if not results:
            rows = db.fetchall(
                "SELECT * FROM opcodes WHERE tc_name LIKE ?",
                (f"%{query}%",))
            results.extend(rows)

        # Try as handler address
        if not results and query.startswith("0x"):
            try:
                ea = int(query, 16)
                rows = db.fetchall(
                    "SELECT * FROM opcodes WHERE handler_ea = ?", (ea,))
                results.extend(rows)
            except ValueError:
                pass

        if direction:
            results = [r for r in results if r["direction"] == direction]

        return {"opcodes": [dict(r) for r in results]}

    def tool_get_wire_format(self, args):
        db = self._session.db
        jam_name = args.get("jam_name", "")

        row = db.fetchone(
            "SELECT * FROM jam_types WHERE name = ?", (jam_name,))
        if not row:
            # Try partial match
            row = db.fetchone(
                "SELECT * FROM jam_types WHERE name LIKE ?",
                (f"%{jam_name}%",))

        if not row:
            return {"error": f"JAM type '{jam_name}' not found"}

        result = dict(row)
        if result.get("fields_json"):
            result["fields"] = json.loads(result["fields_json"])
        return result

    def tool_list_jam_types(self, args):
        db = self._session.db
        filt = args.get("filter", "")
        limit = int(args.get("limit", 50))

        if filt:
            rows = db.fetchall(
                "SELECT name, status, field_count FROM jam_types "
                "WHERE name LIKE ? ORDER BY name LIMIT ?",
                (f"%{filt}%", limit))
        else:
            rows = db.fetchall(
                "SELECT name, status, field_count FROM jam_types "
                "ORDER BY name LIMIT ?", (limit,))

        return {"jam_types": [dict(r) for r in rows],
                "count": len(rows)}

    def tool_lookup_db2(self, args):
        db = self._session.db
        name = args.get("name", "")

        row = db.fetchone(
            "SELECT * FROM db2_tables WHERE name = ?", (name,))
        if not row:
            row = db.fetchone(
                "SELECT * FROM db2_tables WHERE name LIKE ?",
                (f"%{name}%",))

        if not row:
            return {"error": f"DB2 table '{name}' not found"}
        return dict(row)

    def tool_list_db2_tables(self, args):
        db = self._session.db
        filt = args.get("filter", "")
        limit = int(args.get("limit", 50))

        if filt:
            rows = db.fetchall(
                "SELECT name, field_count, record_size, file_data_id "
                "FROM db2_tables WHERE name LIKE ? ORDER BY name LIMIT ?",
                (f"%{filt}%", limit))
        else:
            rows = db.fetchall(
                "SELECT name, field_count, record_size, file_data_id "
                "FROM db2_tables ORDER BY name LIMIT ?", (limit,))

        return {"tables": [dict(r) for r in rows], "count": len(rows)}

    def tool_get_vtable(self, args):
        db = self._session.db
        class_name = args.get("class_name", "")

        vt = db.fetchone(
            "SELECT * FROM vtables WHERE class_name LIKE ?",
            (f"%{class_name}%",))
        if not vt:
            return {"error": f"No vtable found for '{class_name}'"}

        entries = db.fetchall(
            "SELECT * FROM vtable_entries WHERE vtable_ea = ? "
            "ORDER BY slot_index", (vt["ea"],))

        return {
            "vtable": dict(vt),
            "entries": [dict(e) for e in entries],
        }

    def tool_get_class_hierarchy(self, args):
        db = self._session.db
        class_name = args.get("class_name", "")

        chain = []
        current = class_name
        visited = set()

        while current and current not in visited:
            visited.add(current)
            row = db.fetchone(
                "SELECT * FROM vtables WHERE class_name LIKE ?",
                (f"%{current}%",))
            if row:
                chain.append({
                    "class_name": row["class_name"],
                    "ea": f"0x{row['ea']:X}" if row["ea"] else None,
                    "entry_count": row["entry_count"],
                    "source": row["source"],
                })
                current = row["parent_class"]
            else:
                break

        return {"hierarchy": chain}

    def tool_search_functions(self, args):
        db = self._session.db
        query = args.get("query", "")
        system = args.get("system")
        limit = int(args.get("limit", 50))

        if system and query:
            rows = db.fetchall(
                "SELECT ea, rva, name, system, subsystem FROM functions "
                "WHERE system = ? AND name LIKE ? ORDER BY name LIMIT ?",
                (system, f"%{query}%", limit))
        elif system:
            rows = db.fetchall(
                "SELECT ea, rva, name, system, subsystem FROM functions "
                "WHERE system = ? ORDER BY name LIMIT ?",
                (system, limit))
        elif query:
            rows = db.fetchall(
                "SELECT ea, rva, name, system, subsystem FROM functions "
                "WHERE name LIKE ? ORDER BY name LIMIT ?",
                (f"%{query}%", limit))
        else:
            rows = db.fetchall(
                "SELECT ea, rva, name, system, subsystem FROM functions "
                "ORDER BY name LIMIT ?", (limit,))

        results = []
        for r in rows:
            d = dict(r)
            d["ea"] = f"0x{d['ea']:X}" if d["ea"] else None
            results.append(d)

        return {"functions": results, "count": len(results)}

    def tool_classify_function(self, args):
        db = self._session.db
        cfg = self._session.cfg

        addr_str = args.get("address", "")
        system = args.get("system", "")
        subsystem = args.get("subsystem")

        ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
        db.upsert_function(ea, system=system, subsystem=subsystem)
        db.commit()

        return {"status": "ok", "address": f"0x{ea:X}",
                "system": system, "subsystem": subsystem}

    def tool_get_housing_overview(self, args):
        db = self._session.db

        opcodes = db.fetchall(
            """SELECT * FROM opcodes
               WHERE tc_name LIKE '%Housing%' OR tc_name LIKE '%Neighborhood%'
                  OR tc_name LIKE '%Decor%' OR tc_name LIKE '%House%'
                  OR jam_type LIKE '%House%' OR jam_type LIKE '%Neighborhood%'
               ORDER BY direction, internal_index""")

        jams = db.fetchall(
            """SELECT * FROM jam_types
               WHERE name LIKE '%House%' OR name LIKE '%Neighborhood%'
                  OR name LIKE '%Decor%' OR name LIKE '%Housing%'
               ORDER BY name""")

        db2s = db.fetchall(
            """SELECT * FROM db2_tables
               WHERE name LIKE '%House%' OR name LIKE '%Neighborhood%'
                  OR name LIKE '%Decor%' OR name LIKE '%Housing%'
                  OR name LIKE '%Room%' OR name LIKE '%Interior%'
               ORDER BY name""")

        funcs = db.fetchall(
            """SELECT ea, name, system, subsystem FROM functions
               WHERE system IN ('housing', 'neighborhood')
                  OR name LIKE '%Housing%' OR name LIKE '%Neighborhood%'
               ORDER BY name LIMIT 200""")

        return {
            "opcodes": [dict(r) for r in opcodes],
            "jam_types": [dict(r) for r in jams],
            "db2_tables": [dict(r) for r in db2s],
            "functions": [{**dict(r), "ea": f"0x{r['ea']:X}"} for r in funcs],
            "summary": {
                "opcode_count": len(opcodes),
                "jam_type_count": len(jams),
                "db2_table_count": len(db2s),
                "function_count": len(funcs),
            },
        }

    def tool_get_opcode_handler_chain(self, args):
        db = self._session.db
        query = args.get("opcode_name", "")

        row = db.fetchone(
            "SELECT * FROM opcodes WHERE tc_name LIKE ?",
            (f"%{query}%",))
        if not row:
            try:
                idx = int(query, 16) if query.startswith("0x") else int(query)
                row = db.fetchone(
                    "SELECT * FROM opcodes WHERE internal_index = ?", (idx,))
            except ValueError:
                pass

        if not row:
            return {"error": f"Opcode '{query}' not found"}

        chain = {"opcode": dict(row)}

        # Get JAM type info
        if row["jam_type"]:
            jam_row = db.fetchone(
                "SELECT * FROM jam_types WHERE name = ?",
                (row["jam_type"],))
            if jam_row:
                jam_info = dict(jam_row)
                if jam_info.get("fields_json"):
                    jam_info["fields"] = json.loads(jam_info["fields_json"])
                chain["jam_type"] = jam_info

        # Get handler function info
        if row["handler_ea"]:
            func_row = db.fetchone(
                "SELECT * FROM functions WHERE ea = ?",
                (row["handler_ea"],))
            if func_row:
                chain["handler_function"] = dict(func_row)

        return chain

    def tool_get_update_fields(self, args):
        db = self._session.db
        obj_type = args.get("object_type", "")

        rows = db.fetchall(
            "SELECT * FROM update_fields WHERE object_type LIKE ? "
            "ORDER BY field_offset",
            (f"%{obj_type}%",))

        return {"fields": [dict(r) for r in rows], "count": len(rows)}

    def tool_get_lua_api(self, args):
        db = self._session.db
        query = args.get("query", "")

        rows = db.fetchall(
            """SELECT * FROM lua_api
               WHERE method LIKE ? OR namespace LIKE ?
               ORDER BY namespace, method LIMIT 50""",
            (f"%{query}%", f"%{query}%"))

        return {"functions": [dict(r) for r in rows], "count": len(rows)}

    def tool_get_db_stats(self, args):
        db = self._session.db
        stats = db.get_stats()

        last_import = db.kv_get("last_import")

        return {
            "tables": stats,
            "total_records": sum(stats.values()),
            "last_import": last_import,
        }

    def tool_annotate_function(self, args):
        import time
        db = self._session.db

        addr_str = args.get("address", "")
        ann_type = args.get("annotation_type", "comment")
        value = args.get("value", "")

        ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

        db.execute(
            """INSERT OR REPLACE INTO annotations
               (ea, ann_type, value, source, confidence, created_at)
               VALUES (?, ?, ?, 'mcp', 100, ?)""",
            (ea, ann_type, value, time.time()))
        db.commit()

        return {"status": "ok", "address": f"0x{ea:X}",
                "annotation_type": ann_type}

    def tool_cross_reference(self, args):
        db = self._session.db

        addr_str = args.get("address", "")
        ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)

        result = {"address": f"0x{ea:X}", "references": {}}

        # Check all tables
        func = db.fetchone("SELECT * FROM functions WHERE ea = ?", (ea,))
        if func:
            result["references"]["function"] = dict(func)

        opcode = db.fetchone(
            "SELECT * FROM opcodes WHERE handler_ea = ?", (ea,))
        if opcode:
            result["references"]["opcode"] = dict(opcode)

        jam = db.fetchone(
            "SELECT * FROM jam_types WHERE serializer_ea = ? "
            "OR deserializer_ea = ?", (ea, ea))
        if jam:
            result["references"]["jam_type"] = dict(jam)

        lua = db.fetchone(
            "SELECT * FROM lua_api WHERE handler_ea = ?", (ea,))
        if lua:
            result["references"]["lua_api"] = dict(lua)

        vte = db.fetchone(
            "SELECT * FROM vtable_entries WHERE func_ea = ?", (ea,))
        if vte:
            result["references"]["vtable_entry"] = dict(vte)

        ann = db.fetchall(
            "SELECT * FROM annotations WHERE ea = ?", (ea,))
        if ann:
            result["references"]["annotations"] = [dict(a) for a in ann]

        return result
