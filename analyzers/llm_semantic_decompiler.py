"""
LLM-Powered Semantic Decompilation Analyzer

Feeds Hex-Rays pseudocode together with ALL accumulated analyzer context
(wire formats, constraints, enums, constants, behavioural specs, conformance
data, taint analysis, object layouts, state machines, call-graph analytics,
and cross-synthesis results) to a configurable LLM endpoint.  The LLM
produces human-quality named C++ with game-domain comments.

The response is parsed to extract:
  - Clean C++ translation
  - Variable rename mappings (v1 -> playerGuid)
  - Identified magic constants (0x420127 -> HOUSING_PLOT_FLAG_OWNED)
  - Inline game-logic comments
  - A quality score (0-100) measuring coverage of renames/constants

Results are stored in kv_store under "llm_semantic_decompilation" and can
optionally be applied back to the IDB (variable renames, function/line
comments) via the ida_hexrays and ida_funcs APIs.

Entry points:
  semantically_decompile_all(session)        -> int  (batch, all CMSG handlers)
  semantically_decompile_function(session, ea) -> dict (single function)

Helper accessors:
  get_semantic_decompilation(session)          -> full stored result dict
  get_handler_decompilation(session, name)     -> single handler result
  apply_decompilation_to_idb(session, name)    -> apply renames/comments
  export_clean_handlers(session, output_dir)   -> write .cpp files to disk
"""

import json
import os
import re
import time
import traceback
import urllib.request
import urllib.error
from collections import OrderedDict

import ida_funcs
import ida_name
import idautils
import idaapi

from tc_wow_analyzer.core.utils import (
    msg, msg_info, msg_warn, msg_error, ea_str, get_decompiled_text
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KV_KEY = "llm_semantic_decompilation"

# Analyzer data sources to gather context from.
# (human_label, kv_store_key)
_KV_CONTEXT_SOURCES = [
    ("wire_format",         "wire_formats"),
    ("symbolic_constraints", "symbolic_constraints"),
    ("behavioral_spec",     "behavioral_specs"),
    ("conformance",         "conformance_report"),
    ("taint_analysis",      "taint_analysis"),
    ("game_constants",      "game_constants"),
    ("enum_recovery",       "enum_recovery"),
    ("validation_extractor", "validation_comparison_report"),
    ("binary_tc_alignment", "binary_tc_alignment_report"),
    ("call_graph_analytics", "call_graph_analytics"),
    ("return_value_semantics", "return_value_semantics"),
    ("object_layout",       "object_layouts"),
    ("state_machines",      "state_machines"),
    ("cross_synthesis",     "synthesis_report"),
    ("transpiled",          "transpiled_handlers"),
    ("callee_contracts",    "callee_contracts"),
    ("response_packets",    "response_packets"),
    ("protocol_sequences",  "protocol_sequences"),
]

# Maximum characters of pseudocode sent to the LLM (safety cap).
_MAX_PSEUDOCODE_CHARS = 24_000

# Maximum characters of context injected into prompt.
_MAX_CONTEXT_CHARS = 32_000

# Default delay between LLM calls in batch mode (seconds).
_DEFAULT_RATE_LIMIT_SECONDS = 1.0

# Regex patterns for response parsing.
_RE_CODE_BLOCK = re.compile(
    r'```(?:cpp|c\+\+|c)?\s*\n(.*?)```',
    re.DOTALL
)
_RE_VARIABLE_MAP_SECTION = re.compile(
    r'(?:##?\s*)?Variable\s+Mapp?ing[:\s]*\n(.*?)(?:\n##|\n```|\Z)',
    re.DOTALL | re.IGNORECASE
)
_RE_VARIABLE_LINE = re.compile(
    r'^\s*(\w+)\s*[-=:>]+\s*(\w+)',
    re.MULTILINE
)
_RE_CONSTANT_MAP_SECTION = re.compile(
    r'(?:##?\s*)?(?:Identified\s+)?Constants?[:\s]*\n(.*?)(?:\n##|\n```|\Z)',
    re.DOTALL | re.IGNORECASE
)
_RE_CONSTANT_LINE = re.compile(
    r'^\s*(0x[0-9A-Fa-f]+|\d+)\s*[-=:>]+\s*(\w+)',
    re.MULTILINE
)
_RE_COMMENT_SECTION = re.compile(
    r'(?:##?\s*)?Comments?[:\s]*\n(.*?)(?:\n##|\n```|\Z)',
    re.DOTALL | re.IGNORECASE
)
_RE_COMMENT_LINE = re.compile(
    r'^\s*[-*]\s*(.+)', re.MULTILINE
)


# ===================================================================
# LLM Communication
# ===================================================================

class LLMClient:
    """Chat-completion client supporting Claude CLI, Anthropic API, and
    OpenAI-compatible endpoints.

    Reads config from session.cfg ``llm`` section.

    Provider selection (``provider`` key):
      - ``"claude-cli"`` (default): Invokes the ``claude`` CLI binary via
        subprocess in print mode (``-p``).  Uses your existing Claude Code
        subscription — **no API key needed**.
      - ``"anthropic"``: Direct Anthropic Messages API (needs ``api_key``).
      - ``"openai"``: Any OpenAI-compatible endpoint.
      - ``"lmstudio"``: LM Studio (localhost:1234).
      - ``"ollama"``: Ollama (localhost:11434).

    Auto-detection when ``provider`` is unset:
      - URL contains ``anthropic.com`` → anthropic
      - URL contains ``11434`` → ollama
      - URL contains ``127.0.0.1`` or ``localhost`` → openai (LM Studio default)
      - Otherwise → claude-cli

    Config examples::

        # Claude CLI (subscription, no API key needed)
        "llm": {"provider": "claude-cli", "model": "sonnet"}

        # Anthropic API (needs API key)
        "llm": {"provider": "anthropic", "api_key": "sk-ant-...",
                "model": "claude-sonnet-4-20250514"}

        # LM Studio
        "llm": {"provider": "lmstudio", "model": "deepseek-coder-v2"}

        # Ollama
        "llm": {"provider": "ollama", "model": "llama3"}

        # Custom OpenAI-compatible endpoint
        "llm": {"provider": "openai",
                "url": "http://my-server:8080/v1/chat/completions",
                "model": "my-model"}
    """

    def __init__(self, session):
        llm_cfg = session.cfg.get("llm") or {}
        self.url = llm_cfg.get("url", "")
        self.model = llm_cfg.get("model", "sonnet")
        self.api_key = llm_cfg.get("api_key", "")
        self.timeout = int(llm_cfg.get("timeout", 180))
        self.max_tokens = int(llm_cfg.get("max_tokens", 8192))
        self.temperature = float(llm_cfg.get("temperature", 0.2))

        # Provider aliases → canonical name + default URL
        _PROVIDER_MAP = {
            "claude-cli":  ("claude-cli", ""),
            "claude_cli":  ("claude-cli", ""),
            "cli":         ("claude-cli", ""),
            "anthropic":   ("anthropic",  "https://api.anthropic.com/v1/messages"),
            "claude":      ("anthropic",  "https://api.anthropic.com/v1/messages"),
            "openai":      ("openai",     "http://127.0.0.1:1234/v1/chat/completions"),
            "local":       ("openai",     "http://127.0.0.1:1234/v1/chat/completions"),
            "lmstudio":    ("openai",     "http://127.0.0.1:1234/v1/chat/completions"),
            "lm-studio":   ("openai",     "http://127.0.0.1:1234/v1/chat/completions"),
            "lm_studio":   ("openai",     "http://127.0.0.1:1234/v1/chat/completions"),
            "ollama":      ("openai",     "http://127.0.0.1:11434/v1/chat/completions"),
        }

        provider = llm_cfg.get("provider", "").lower().strip()
        if provider in _PROVIDER_MAP:
            self._provider, default_url = _PROVIDER_MAP[provider]
            if not self.url:
                self.url = default_url
        elif "anthropic.com" in self.url:
            self._provider = "anthropic"
        elif "11434" in self.url:
            self._provider = "openai"  # ollama
        elif self.url and ("127.0.0.1" in self.url or "localhost" in self.url):
            self._provider = "openai"
        else:
            self._provider = "claude-cli"

    # ------------------------------------------------------------------

    def chat(self, system_prompt, user_prompt):
        """Send a chat completion request and return the assistant text.

        Returns (response_text, error_string).  On success error_string
        is None; on failure response_text is None.
        """
        if self._provider == "claude-cli":
            return self._chat_claude_cli(system_prompt, user_prompt)
        if self._provider == "anthropic":
            return self._chat_anthropic(system_prompt, user_prompt)
        return self._chat_openai(system_prompt, user_prompt)

    def _chat_claude_cli(self, system_prompt, user_prompt):
        """Invoke claude CLI in print mode via subprocess."""
        import subprocess
        import shutil

        claude_bin = shutil.which("claude")
        if not claude_bin:
            return None, ("'claude' CLI not found in PATH. "
                          "Install Claude Code or set provider to 'anthropic'/'openai'.")

        # Build the combined prompt (system + user)
        full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"

        cmd = [
            claude_bin, "-p",
            "--model", self.model,
            "--allowedTools", "",       # no tools, pure text completion
            "--max-turns", "1",         # single turn, no back-and-forth
        ]

        # Unset CLAUDECODE env var to allow nested invocation (IDA may be
        # running inside a Claude Code session)
        env = dict(os.environ)
        env.pop("CLAUDECODE", None)

        try:
            result = subprocess.run(
                cmd,
                input=full_prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
            )
        except subprocess.TimeoutExpired:
            return None, f"Claude CLI timed out after {self.timeout}s"
        except FileNotFoundError:
            return None, "Claude CLI binary not found"
        except Exception as exc:
            return None, f"Claude CLI error: {exc}"

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:500]
            return None, f"Claude CLI exit code {result.returncode}: {stderr}"

        text = (result.stdout or "").strip()
        if not text:
            return None, "Empty response from Claude CLI"
        return text, None

    def _chat_openai(self, system_prompt, user_prompt):
        """OpenAI-compatible chat completion."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data, error = self._http_post(payload, headers)
        if error:
            return None, error

        try:
            choices = data.get("choices", [])
            if not choices:
                return None, "Empty choices in LLM response"
            text = choices[0].get("message", {}).get("content", "")
            if not text:
                return None, "Empty content in LLM response"
            return text, None
        except Exception as exc:
            return None, f"Response parse error: {exc}"

    def _chat_anthropic(self, system_prompt, user_prompt):
        """Anthropic Messages API chat completion."""
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key

        data, error = self._http_post(payload, headers)
        if error:
            return None, error

        try:
            content = data.get("content", [])
            if not content:
                return None, "Empty content in Anthropic response"
            text_parts = [
                block.get("text", "")
                for block in content
                if block.get("type") == "text"
            ]
            text = "\n".join(text_parts)
            if not text:
                return None, "No text blocks in Anthropic response"
            return text, None
        except Exception as exc:
            return None, f"Response parse error: {exc}"

    def _http_post(self, payload, headers):
        """Send HTTP POST and return (parsed_json, error_string)."""
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=body, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data, None
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            return None, f"HTTP {exc.code}: {err_body}"
        except urllib.error.URLError as exc:
            return None, f"Connection error: {exc.reason}"
        except Exception as exc:
            return None, f"Request error: {exc}"

    def provider_label(self):
        """Human-readable label for logging."""
        if self._provider == "claude-cli":
            return f"claude-cli / {self.model}"
        return f"{self._provider}: {self.url} / {self.model}"


# ===================================================================
# Context Gathering (Phase 1)
# ===================================================================

def _gather_context(session, ea):
    """Pull ALL available analysis context for the function at *ea*.

    Returns a dict keyed by context category (wire_format, constraints,
    enums, constants, tc_source, etc.) with the relevant data as strings
    ready for prompt injection.
    """
    db = session.db
    ctx = OrderedDict()

    # ---- Opcode / handler metadata from the opcodes table ----
    row = db.fetchone(
        "SELECT * FROM opcodes WHERE handler_ea = ?", (ea,)
    )
    opcode_name = None
    tc_name = None
    jam_type_name = None
    if row:
        opcode_name = row["tc_name"] or f"CMSG_idx_{row['internal_index']}"
        tc_name = row["tc_name"]
        jam_type_name = row["jam_type"]
        ctx["opcode_info"] = (
            f"Direction: {row['direction']}\n"
            f"Internal index: 0x{row['internal_index']:X}\n"
            f"TC name: {tc_name or '(unknown)'}\n"
            f"JAM type: {jam_type_name or '(unknown)'}\n"
            f"Status: {row['status']}"
        )

    # ---- JAM type fields from jam_types table ----
    if jam_type_name:
        jt = db.fetchone(
            "SELECT * FROM jam_types WHERE name = ?", (jam_type_name,)
        )
        if jt and jt["fields_json"]:
            try:
                fields = json.loads(jt["fields_json"])
                lines = []
                for f in fields:
                    if isinstance(f, dict):
                        fname = f.get("name", "?")
                        ftype = f.get("type", "?")
                        fsize = f.get("size", "?")
                        lines.append(f"  {ftype:12s} {fname} (size={fsize})")
                    else:
                        lines.append(f"  {f}")
                ctx["jam_fields"] = "\n".join(lines)
            except Exception:
                pass

    # ---- VTable / class hierarchy ----
    vtrow = db.fetchone(
        "SELECT v.class_name, v.parent_class "
        "FROM vtable_entries ve "
        "JOIN vtables v ON ve.vtable_ea = v.ea "
        "WHERE ve.func_ea = ?",
        (ea,)
    )
    if vtrow:
        ctx["class_info"] = (
            f"Class: {vtrow['class_name'] or '?'}\n"
            f"Parent: {vtrow['parent_class'] or '?'}"
        )

    # ---- Function classification ----
    frow = db.fetchone("SELECT * FROM functions WHERE ea = ?", (ea,))
    if frow:
        parts = []
        if frow["system"]:
            parts.append(f"System: {frow['system']}")
        if frow["subsystem"]:
            parts.append(f"Subsystem: {frow['subsystem']}")
        if frow["name"]:
            parts.append(f"Name: {frow['name']}")
        if parts:
            ctx["function_classification"] = "\n".join(parts)

    # ---- Pull from kv_store analyzer outputs ----
    handler_key = tc_name or ea_str(ea)

    for label, kv_key in _KV_CONTEXT_SOURCES:
        blob = db.kv_get(kv_key)
        if blob is None:
            continue

        # Many analyzers store their output as a dict with per-handler
        # sub-keys.  We look for our handler in several ways.
        snippet = _extract_handler_snippet(blob, handler_key, ea)
        if snippet:
            ctx[label] = snippet

    # ---- TC source snippet (if available) ----
    tc_source = _find_tc_source(session, tc_name)
    if tc_source:
        ctx["tc_source"] = tc_source

    return ctx, opcode_name, tc_name


def _extract_handler_snippet(blob, handler_key, ea):
    """Try to extract the portion of a kv-store blob relevant to a handler.

    Many analyzers store either:
      - A top-level dict with handler names or hex EAs as keys
      - A dict with a nested "results" or "handlers" or "profiles" sub-dict
      - A flat list that must be searched

    Returns a JSON-formatted string (truncated) or None.
    """
    if not isinstance(blob, dict):
        return None

    # Direct key lookup variants
    for key_attempt in [handler_key, ea_str(ea), str(ea), f"0x{ea:X}", f"0x{ea:x}"]:
        if key_attempt and key_attempt in blob:
            return _truncate_json(blob[key_attempt], 4000)

    # Nested container lookup
    for container_key in ("results", "handlers", "handler_profiles",
                          "profiles", "handler_results", "per_handler"):
        container = blob.get(container_key)
        if isinstance(container, dict):
            for key_attempt in [handler_key, ea_str(ea), str(ea)]:
                if key_attempt and key_attempt in container:
                    return _truncate_json(container[key_attempt], 4000)
        elif isinstance(container, list):
            for entry in container:
                if isinstance(entry, dict):
                    ename = entry.get("name") or entry.get("handler") or entry.get("tc_name")
                    eea = entry.get("ea") or entry.get("handler_ea")
                    if ename == handler_key or eea == ea:
                        return _truncate_json(entry, 4000)

    return None


def _truncate_json(obj, max_chars):
    """Serialize obj to JSON and truncate to max_chars."""
    try:
        text = json.dumps(obj, indent=1, default=str)
    except Exception:
        text = str(obj)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... (truncated)"
    return text


def _find_tc_source(session, tc_name):
    """Attempt to load matching TrinityCore handler source from disk.

    Uses the configured tc_source_dir to search for files containing the
    handler function name.  Returns the first match (up to 200 lines),
    or None.
    """
    if not tc_name:
        return None
    src_dir = session.cfg.tc_source_dir
    if not src_dir or not os.path.isdir(src_dir):
        return None

    # Derive likely file names from the TC handler name.
    # HandleFooBar -> look in Handlers/ directories.
    search_name = tc_name
    if search_name.startswith("Handle"):
        search_name = search_name[6:]  # "FooBar"

    # Walk common handler locations
    search_dirs = [
        os.path.join(src_dir, "src", "server", "game", "Handlers"),
        os.path.join(src_dir, "src", "server", "game"),
        os.path.join(src_dir, "src", "server", "scripts"),
    ]

    for sdir in search_dirs:
        if not os.path.isdir(sdir):
            continue
        for root, _dirs, files in os.walk(sdir):
            for fname in files:
                if not fname.endswith(".cpp") and not fname.endswith(".h"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    if tc_name in content:
                        # Extract the function body (rough heuristic)
                        return _extract_function_body(content, tc_name, 200)
                except Exception:
                    continue
    return None


def _extract_function_body(source, func_name, max_lines=200):
    """Extract the body of *func_name* from a C++ source string.

    Returns up to *max_lines* starting from the function signature.
    """
    idx = source.find(func_name)
    if idx < 0:
        return None

    # Walk backwards to find the beginning of the line
    line_start = source.rfind("\n", 0, idx)
    if line_start < 0:
        line_start = 0
    else:
        line_start += 1

    # Take lines forward
    lines = source[line_start:].split("\n")[:max_lines]
    # Try to detect end of function (matching braces)
    depth = 0
    result_lines = []
    started = False
    for line in lines:
        result_lines.append(line)
        if "{" in line:
            depth += line.count("{") - line.count("}")
            started = True
        elif "}" in line:
            depth += line.count("{") - line.count("}")
        if started and depth <= 0:
            break
    return "\n".join(result_lines)


# ===================================================================
# Prompt Construction (Phase 2)
# ===================================================================

_SYSTEM_PROMPT = """\
You are an expert World of Warcraft server reverse engineer.  You are \
given the Hex-Rays decompiled pseudocode of a packet handler function \
from the WoW x86-64 client binary.  Your task is to produce clean, \
human-readable C++ with meaningful names and comments that could serve \
as a reference for TrinityCore server implementation.

Rules:
1. Rename ALL variables to meaningful game-domain names.
2. Replace magic numbers with named constants or enums.
3. Add short inline comments explaining game logic.
4. Identify struct/class member accesses and name them.
5. Preserve the control flow exactly — do not optimise away branches.
6. Use TrinityCore naming conventions (PascalCase methods, _member fields).
7. Where context is insufficient, use descriptive placeholder names \
   (e.g. unknownField_0x38) rather than leaving IDA names.

Output format — provide ALL three sections in this exact order:

```cpp
// Your clean C++ here
```

## Variable Mapping
v1 -> meaningfulName
v2 -> anotherName

## Constants
0xABCD -> CONSTANT_NAME

## Comments
- Line 15: Validates plot ownership before allowing edit
- Line 42: Sends error response SMSG_HOUSING_ERROR
"""


def _build_user_prompt(pseudocode, context, opcode_name, tc_name):
    """Construct the user-message portion of the prompt."""
    parts = []

    # Header
    parts.append(f"## Function: {tc_name or '(unknown)'}")
    if opcode_name:
        parts.append(f"## Opcode: {opcode_name}")
    parts.append("")

    # Pseudocode
    code = pseudocode
    if len(code) > _MAX_PSEUDOCODE_CHARS:
        code = code[:_MAX_PSEUDOCODE_CHARS] + "\n// ... (truncated)"
    parts.append("## Decompiled Pseudocode:")
    parts.append(f"```c\n{code}\n```")
    parts.append("")

    # Context sections — honour a total budget
    budget = _MAX_CONTEXT_CHARS
    for label, text in context.items():
        section = f"## {_label_to_heading(label)}:\n{text}\n"
        if len(section) > budget:
            section = section[:budget] + "\n... (truncated)\n"
            budget = 0
        else:
            budget -= len(section)
        parts.append(section)
        if budget <= 0:
            parts.append("(remaining context truncated due to size)")
            break

    return "\n".join(parts)


def _label_to_heading(label):
    """Convert a snake_case label to a Title Case heading."""
    return label.replace("_", " ").title()


# ===================================================================
# Response Parsing (Phase 3)
# ===================================================================

def _parse_llm_response(response_text):
    """Parse the structured LLM response.

    Returns a dict with keys: clean_cpp, variable_map, constants_identified,
    comments, quality_score, parse_warnings.
    """
    result = {
        "clean_cpp": "",
        "variable_map": {},
        "constants_identified": {},
        "comments": [],
        "quality_score": 0,
        "parse_warnings": [],
    }

    if not response_text:
        result["parse_warnings"].append("Empty LLM response")
        return result

    # ---- Extract C++ code block ----
    code_match = _RE_CODE_BLOCK.search(response_text)
    if code_match:
        result["clean_cpp"] = code_match.group(1).strip()
    else:
        # Fallback: if no fenced block, treat the whole response as code
        # up to the first "## Variable" heading.
        cutoff = response_text.find("## Variable")
        if cutoff < 0:
            cutoff = response_text.find("## Constants")
        if cutoff < 0:
            cutoff = len(response_text)
        result["clean_cpp"] = response_text[:cutoff].strip()
        result["parse_warnings"].append(
            "No fenced code block found; used heuristic extraction"
        )

    # ---- Variable mapping ----
    var_section = _RE_VARIABLE_MAP_SECTION.search(response_text)
    if var_section:
        for m in _RE_VARIABLE_LINE.finditer(var_section.group(1)):
            old_name = m.group(1)
            new_name = m.group(2)
            # Sanity: skip if old == new or if names are too short
            if old_name != new_name and len(new_name) > 1:
                result["variable_map"][old_name] = new_name

    # ---- Constants ----
    const_section = _RE_CONSTANT_MAP_SECTION.search(response_text)
    if const_section:
        for m in _RE_CONSTANT_LINE.finditer(const_section.group(1)):
            raw_value = m.group(1)
            const_name = m.group(2)
            if len(const_name) > 2:
                result["constants_identified"][raw_value] = const_name

    # ---- Comments ----
    comment_section = _RE_COMMENT_SECTION.search(response_text)
    if comment_section:
        for m in _RE_COMMENT_LINE.finditer(comment_section.group(1)):
            result["comments"].append(m.group(1).strip())

    # ---- Quality score ----
    result["quality_score"] = _compute_quality_score(result)

    return result


def _compute_quality_score(parsed):
    """Compute a 0-100 quality score based on how much was extracted."""
    score = 0

    # Has clean C++?
    cpp = parsed.get("clean_cpp", "")
    if cpp:
        score += 20
        # Bonus for length (indicates real transformation, not echo)
        if len(cpp) > 200:
            score += 10
        if len(cpp) > 1000:
            score += 5

    # Variable renames
    n_vars = len(parsed.get("variable_map", {}))
    if n_vars > 0:
        score += min(25, n_vars * 3)  # cap at 25

    # Constants identified
    n_consts = len(parsed.get("constants_identified", {}))
    if n_consts > 0:
        score += min(20, n_consts * 4)  # cap at 20

    # Comments
    n_comments = len(parsed.get("comments", []))
    if n_comments > 0:
        score += min(15, n_comments * 3)  # cap at 15

    # No parse warnings
    if not parsed.get("parse_warnings"):
        score += 5

    return min(100, score)


# ===================================================================
# NOPROP helper (IDA 9.3+)
# ===================================================================

def _set_lvar_noprop(cfunc, lvar):
    """Mark a local variable with NOPROP to prevent the decompiler from
    propagating away user-assigned names. Requires IDA 9.3+.

    Uses CVAR_NOPROP on the lvar_saved_info_t entry, and LVINF_NOPROP
    on the lvar itself (whichever is available in this IDA version).
    """
    try:
        import ida_hexrays
        # Try LVINF_NOPROP flag on the lvar itself (simplest approach)
        if hasattr(ida_hexrays, 'LVINF_NOPROP'):
            lvar.flags |= ida_hexrays.LVINF_NOPROP
            return
        # Try CVAR_NOPROP on lvar_saved_info_t
        if hasattr(ida_hexrays, 'CVAR_NOPROP'):
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.name = lvar.name
            lsi.type = lvar.type()
            lsi.flags = ida_hexrays.CVAR_NOPROP
            ida_hexrays.modify_user_lvar_info(cfunc.entry_ea,
                                               ida_hexrays.MLI_NAME | ida_hexrays.MLI_FLAGS,
                                               lsi)
    except (AttributeError, Exception):
        pass  # Pre-9.3 IDA — silently skip


# ===================================================================
# IDB Application (Phase 4)
# ===================================================================

def _apply_to_idb(ea, parsed, force=False):
    """Apply variable renames and comments from *parsed* back to the IDB.

    Requires ida_hexrays for variable renames.  Function-level comments
    are applied via ida_funcs.

    Args:
        ea: Function start address.
        parsed: Dict from _parse_llm_response.
        force: If True, overwrite existing comments.

    Returns:
        Number of changes applied.
    """
    changes = 0

    # ---- Function comment (clean C++ as posterior comment) ----
    clean_cpp = parsed.get("clean_cpp", "")
    if clean_cpp:
        import ida_bytes
        existing = ida_funcs.get_func_cmt(ea, True) or ""
        if force or not existing:
            # Compose a comment with the clean C++ and identified info
            header_lines = ["[LLM Semantic Decompilation]"]
            for cmt in parsed.get("comments", []):
                header_lines.append(f"  {cmt}")
            if parsed.get("constants_identified"):
                header_lines.append("Constants:")
                for val, name in parsed["constants_identified"].items():
                    header_lines.append(f"  {val} = {name}")
            comment_text = "\n".join(header_lines)
            ida_funcs.set_func_cmt(ea, comment_text, True)
            changes += 1

    # ---- Variable renames via ida_hexrays ----
    var_map = parsed.get("variable_map", {})
    if var_map:
        try:
            from tc_wow_analyzer.core.utils import safe_decompile
            cfunc = safe_decompile(ea)
            if cfunc:
                lvars = cfunc.get_lvars()
                renamed = set()
                for lvar in lvars:
                    old_name = lvar.name
                    if old_name in var_map and old_name not in renamed:
                        new_name = var_map[old_name]
                        # Validate the new name is a legal C identifier
                        if re.match(r'^[a-zA-Z_]\w*$', new_name):
                            if lvar.set_lvar_type(lvar.type()):
                                pass  # just ensure type is set
                            # Rename the variable
                            success = cfunc.set_lvar_name(lvar, new_name)
                            if success:
                                renamed.add(old_name)
                                changes += 1
                                # IDA 9.3+: Set NOPROP flag to prevent the
                                # decompiler from propagating away our rename
                                _set_lvar_noprop(cfunc, lvar)
                if renamed:
                    cfunc.save_user_labels()
                    cfunc.save_user_cmts()
        except ImportError:
            msg_warn("ida_hexrays not available — skipping variable renames")
        except Exception as exc:
            msg_warn(f"Variable rename error at {ea_str(ea)}: {exc}")

    # ---- Anterior comments for key lines ----
    # We add a summary anterior comment at function start
    if parsed.get("comments") and (force or not ida_funcs.get_func_cmt(ea, False)):
        summary = " | ".join(parsed["comments"][:5])
        if len(summary) > 200:
            summary = summary[:200] + "..."
        ida_funcs.set_func_cmt(ea, summary, False)
        changes += 1

    return changes


# ===================================================================
# Single-Function Entry Point
# ===================================================================

def semantically_decompile_function(session, ea, apply_to_idb_flag=False,
                                     rate_limit=0.0):
    """Semantically decompile a single function at *ea*.

    Args:
        session: PluginSession with .db and .cfg.
        ea: Effective address of the function.
        apply_to_idb_flag: If True, apply renames/comments to IDB.
        rate_limit: Seconds to sleep after the LLM call (for batch).

    Returns:
        A result dict (same shape as stored per-handler), or None on
        failure.
    """
    # Validate function exists
    func = ida_funcs.get_func(ea)
    if not func:
        msg_error(f"No function at {ea_str(ea)}")
        return None

    # Get pseudocode
    pseudocode = get_decompiled_text(ea)
    if not pseudocode:
        msg_warn(f"Decompilation failed for {ea_str(ea)}")
        return None

    # Gather context
    context, opcode_name, tc_name = _gather_context(session, ea)
    handler_label = tc_name or ida_name.get_name(ea) or ea_str(ea)

    msg_info(f"Semantic decompilation: {handler_label} at {ea_str(ea)}")
    msg(f"  Context sections: {', '.join(context.keys()) or '(none)'}")

    # Build prompt
    user_prompt = _build_user_prompt(pseudocode, context, opcode_name, tc_name)

    # Call LLM
    llm = LLMClient(session)
    t0 = time.time()
    response_text, error = llm.chat(_SYSTEM_PROMPT, user_prompt)
    elapsed = time.time() - t0

    if error:
        msg_error(f"  LLM error for {handler_label}: {error}")
        return {
            "ea": ea,
            "handler": handler_label,
            "error": error,
            "original_pseudocode": pseudocode[:2000],
            "clean_cpp": "",
            "variable_map": {},
            "constants_identified": {},
            "comments": [],
            "quality_score": 0,
            "applied_to_idb": False,
            "llm_elapsed_seconds": round(elapsed, 2),
        }

    # Parse response
    parsed = _parse_llm_response(response_text)

    msg(f"  LLM responded in {elapsed:.1f}s — "
        f"quality={parsed['quality_score']}, "
        f"vars={len(parsed['variable_map'])}, "
        f"consts={len(parsed['constants_identified'])}, "
        f"comments={len(parsed['comments'])}")

    if parsed["parse_warnings"]:
        for w in parsed["parse_warnings"]:
            msg_warn(f"  Parse warning: {w}")

    # Optionally apply to IDB
    applied = False
    if apply_to_idb_flag:
        n_changes = _apply_to_idb(ea, parsed)
        applied = n_changes > 0
        if applied:
            msg_info(f"  Applied {n_changes} changes to IDB")

    # Rate limit
    if rate_limit > 0:
        time.sleep(rate_limit)

    return {
        "ea": ea,
        "handler": handler_label,
        "original_pseudocode": pseudocode,
        "clean_cpp": parsed["clean_cpp"],
        "variable_map": parsed["variable_map"],
        "constants_identified": parsed["constants_identified"],
        "comments": parsed["comments"],
        "quality_score": parsed["quality_score"],
        "parse_warnings": parsed.get("parse_warnings", []),
        "applied_to_idb": applied,
        "llm_elapsed_seconds": round(elapsed, 2),
        "llm_raw_response": response_text,
    }


# ===================================================================
# Batch Entry Point
# ===================================================================

def semantically_decompile_all(session, force=False,
                                apply_to_idb_flag=False,
                                rate_limit=None,
                                max_handlers=0,
                                direction="CMSG"):
    """Batch-process all handlers of the given direction.

    Args:
        session: PluginSession.
        force: If True, reprocess handlers that already have results.
        apply_to_idb_flag: If True, apply renames/comments per handler.
        rate_limit: Seconds between LLM calls (default from config or 1.0).
        max_handlers: If > 0, stop after this many handlers (for testing).
        direction: "CMSG" or "SMSG".

    Returns:
        Number of handlers successfully processed.
    """
    db = session.db
    t0 = time.time()

    if rate_limit is None:
        llm_cfg = session.cfg.get("llm") or {}
        rate_limit = float(llm_cfg.get("rate_limit", _DEFAULT_RATE_LIMIT_SECONDS))

    # Load existing results
    existing = db.kv_get(KV_KEY) or {}
    existing_results = existing.get("results", {})

    # Get all handlers
    handlers = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = ? AND handler_ea IS NOT NULL "
        "ORDER BY internal_index",
        (direction,)
    )

    if not handlers:
        msg_warn(f"No {direction} handlers found in opcodes table.")
        return 0

    msg_info(f"LLM Semantic Decompiler: {len(handlers)} {direction} handlers")

    llm = LLMClient(session)
    msg_info(f"  LLM endpoint: {llm.provider_label()}")
    msg_info(f"  Rate limit: {rate_limit}s between calls")
    msg_info(f"  Force reprocess: {force}")
    msg_info(f"  Apply to IDB: {apply_to_idb_flag}")

    processed = 0
    skipped = 0
    errors = 0
    total_vars = 0
    total_consts = 0

    for i, row in enumerate(handlers):
        handler_ea = row["handler_ea"]
        tc_name = row["tc_name"] or f"handler_{row['internal_index']:X}"

        # Skip if already processed (unless force)
        if not force and tc_name in existing_results:
            prev = existing_results[tc_name]
            if prev.get("clean_cpp") and prev.get("quality_score", 0) > 0:
                skipped += 1
                continue

        # Progress logging
        msg(f"  [{i + 1}/{len(handlers)}] Processing {tc_name} "
            f"at {ea_str(handler_ea)}...")

        # Process
        result = semantically_decompile_function(
            session, handler_ea,
            apply_to_idb_flag=apply_to_idb_flag,
            rate_limit=rate_limit,
        )

        if result is None:
            errors += 1
            continue

        if result.get("error"):
            errors += 1
            # Still store the error result
            existing_results[tc_name] = result
        else:
            processed += 1
            total_vars += len(result.get("variable_map", {}))
            total_consts += len(result.get("constants_identified", {}))
            existing_results[tc_name] = result

        # Periodic save (every 10 handlers)
        if (processed + errors) % 10 == 0:
            _save_results(db, existing_results, processed, total_vars,
                          total_consts, llm, t0)

        # Max handlers cap
        if max_handlers > 0 and processed >= max_handlers:
            msg_info(f"  Reached max_handlers={max_handlers}, stopping.")
            break

    # Final save
    _save_results(db, existing_results, processed, total_vars,
                  total_consts, llm, t0)

    elapsed = time.time() - t0
    msg_info(f"LLM Semantic Decompilation complete in {elapsed:.1f}s")
    msg_info(f"  Processed: {processed}")
    msg_info(f"  Skipped (already done): {skipped}")
    msg_info(f"  Errors: {errors}")
    msg_info(f"  Total variables renamed: {total_vars}")
    msg_info(f"  Total constants identified: {total_consts}")

    return processed


def _save_results(db, results, handlers_processed, total_vars,
                  total_consts, llm, start_time):
    """Persist current results to kv_store."""
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "provider": llm.provider_label(),
        "handlers_processed": handlers_processed,
        "total_variables_renamed": total_vars,
        "total_constants_identified": total_consts,
        "elapsed_seconds": round(time.time() - start_time, 2),
        "results": results,
    }
    db.kv_set(KV_KEY, report)
    db.commit()


# ===================================================================
# Accessor Helpers
# ===================================================================

def get_semantic_decompilation(session):
    """Retrieve the full stored LLM semantic decompilation report.

    Returns the report dict, or an empty dict if not yet run.
    """
    return session.db.kv_get(KV_KEY) or {}


def get_handler_decompilation(session, handler_name):
    """Retrieve the decompilation result for a single handler.

    Args:
        session: PluginSession.
        handler_name: TC handler name (e.g. "HandleMovement").

    Returns:
        The per-handler result dict, or None if not found.
    """
    report = get_semantic_decompilation(session)
    results = report.get("results", {})
    return results.get(handler_name)


def apply_decompilation_to_idb(session, handler_name, force=False):
    """Apply previously-stored LLM decompilation to the IDB.

    Loads the stored result for *handler_name* and applies variable
    renames and comments.

    Args:
        session: PluginSession.
        handler_name: TC handler name.
        force: Overwrite existing comments.

    Returns:
        Number of IDB changes applied, or -1 on error.
    """
    result = get_handler_decompilation(session, handler_name)
    if not result:
        msg_error(f"No stored decompilation for '{handler_name}'")
        return -1

    ea = result.get("ea")
    if not ea:
        msg_error(f"No EA stored for '{handler_name}'")
        return -1

    parsed = {
        "clean_cpp": result.get("clean_cpp", ""),
        "variable_map": result.get("variable_map", {}),
        "constants_identified": result.get("constants_identified", {}),
        "comments": result.get("comments", []),
    }

    n_changes = _apply_to_idb(ea, parsed, force=force)
    msg_info(f"Applied {n_changes} changes for '{handler_name}' "
             f"at {ea_str(ea)}")

    # Update the stored result
    result["applied_to_idb"] = n_changes > 0
    report = get_semantic_decompilation(session)
    report.setdefault("results", {})[handler_name] = result
    session.db.kv_set(KV_KEY, report)
    session.db.commit()

    return n_changes


def apply_all_to_idb(session, min_quality=50, force=False):
    """Apply all stored decompilations that meet a quality threshold.

    Args:
        session: PluginSession.
        min_quality: Minimum quality_score to apply (0-100).
        force: Overwrite existing IDB comments.

    Returns:
        Total number of handlers applied.
    """
    report = get_semantic_decompilation(session)
    results = report.get("results", {})
    if not results:
        msg_warn("No stored decompilations to apply.")
        return 0

    applied_count = 0
    for handler_name, result in results.items():
        if result.get("quality_score", 0) < min_quality:
            continue
        if result.get("applied_to_idb") and not force:
            continue
        ea = result.get("ea")
        if not ea:
            continue

        parsed = {
            "clean_cpp": result.get("clean_cpp", ""),
            "variable_map": result.get("variable_map", {}),
            "constants_identified": result.get("constants_identified", {}),
            "comments": result.get("comments", []),
        }

        n_changes = _apply_to_idb(ea, parsed, force=force)
        if n_changes > 0:
            result["applied_to_idb"] = True
            applied_count += 1

    # Persist updated flags
    session.db.kv_set(KV_KEY, report)
    session.db.commit()
    msg_info(f"Applied decompilations for {applied_count} handlers "
             f"(min_quality={min_quality})")
    return applied_count


# ===================================================================
# Export Helpers
# ===================================================================

def export_clean_handlers(session, output_dir, min_quality=0):
    """Export all clean C++ handler decompilations to individual files.

    Creates one ``.cpp`` file per handler in *output_dir*.

    Args:
        session: PluginSession.
        output_dir: Directory to write files into (created if absent).
        min_quality: Minimum quality score to export.

    Returns:
        Number of files written.
    """
    report = get_semantic_decompilation(session)
    results = report.get("results", {})
    if not results:
        msg_warn("No stored decompilations to export.")
        return 0

    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for handler_name, result in sorted(results.items()):
        if result.get("quality_score", 0) < min_quality:
            continue
        clean_cpp = result.get("clean_cpp", "")
        if not clean_cpp:
            continue

        # Build the file
        lines = []
        lines.append(f"// Handler: {handler_name}")
        ea = result.get("ea")
        if ea:
            lines.append(f"// Binary EA: {ea_str(ea)}")
        lines.append(f"// Quality Score: {result.get('quality_score', 0)}/100")
        lines.append(f"// LLM Provider: {report.get('provider', 'unknown')}")
        lines.append(f"// Generated: {report.get('timestamp', 'unknown')}")
        lines.append("")

        # Variable mapping as header comment
        var_map = result.get("variable_map", {})
        if var_map:
            lines.append("// Variable Mapping:")
            for old, new in sorted(var_map.items()):
                lines.append(f"//   {old} -> {new}")
            lines.append("")

        # Constants as header comment
        consts = result.get("constants_identified", {})
        if consts:
            lines.append("// Identified Constants:")
            for val, name in sorted(consts.items()):
                lines.append(f"//   {val} = {name}")
            lines.append("")

        # Game logic comments
        comments = result.get("comments", [])
        if comments:
            lines.append("// Game Logic Notes:")
            for cmt in comments:
                lines.append(f"//   {cmt}")
            lines.append("")

        lines.append(clean_cpp)
        lines.append("")

        # Sanitise filename
        safe_name = re.sub(r'[^\w\-]', '_', handler_name)
        fpath = os.path.join(output_dir, f"{safe_name}.cpp")

        try:
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            count += 1
        except Exception as exc:
            msg_error(f"Failed to write {fpath}: {exc}")

    msg_info(f"Exported {count} clean handler files to {output_dir}")
    return count


def export_summary_csv(session, output_path):
    """Export a CSV summary of all decompiled handlers.

    Columns: handler, ea, quality_score, n_vars_renamed,
    n_constants, n_comments, applied_to_idb, llm_elapsed_s
    """
    report = get_semantic_decompilation(session)
    results = report.get("results", {})
    if not results:
        msg_warn("No stored decompilations to export.")
        return 0

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(
                "handler,ea,quality_score,n_vars_renamed,"
                "n_constants,n_comments,applied_to_idb,llm_elapsed_s\n"
            )
            for handler_name, result in sorted(results.items()):
                ea = result.get("ea", 0)
                fh.write(
                    f"{handler_name},"
                    f"{ea_str(ea) if ea else ''},"
                    f"{result.get('quality_score', 0)},"
                    f"{len(result.get('variable_map', {}))},"
                    f"{len(result.get('constants_identified', {}))},"
                    f"{len(result.get('comments', []))},"
                    f"{result.get('applied_to_idb', False)},"
                    f"{result.get('llm_elapsed_seconds', 0)}\n"
                )
    except Exception as exc:
        msg_error(f"Failed to write CSV {output_path}: {exc}")
        return 0

    n = len(results)
    msg_info(f"Exported summary CSV with {n} entries to {output_path}")
    return n


# ===================================================================
# Statistics & Diagnostics
# ===================================================================

def get_decompilation_stats(session):
    """Return a summary statistics dict for the dashboard.

    Keys: total_handlers, avg_quality, total_vars, total_consts,
    quality_distribution (histogram buckets), top_handlers (by quality),
    error_count, provider.
    """
    report = get_semantic_decompilation(session)
    results = report.get("results", {})
    if not results:
        return {
            "total_handlers": 0,
            "avg_quality": 0.0,
            "total_vars": 0,
            "total_consts": 0,
            "quality_distribution": {},
            "top_handlers": [],
            "error_count": 0,
            "provider": report.get("provider", "unknown"),
        }

    qualities = []
    total_vars = 0
    total_consts = 0
    error_count = 0
    handler_scores = []

    for name, r in results.items():
        if r.get("error"):
            error_count += 1
            continue
        q = r.get("quality_score", 0)
        qualities.append(q)
        total_vars += len(r.get("variable_map", {}))
        total_consts += len(r.get("constants_identified", {}))
        handler_scores.append((name, q))

    avg_q = sum(qualities) / len(qualities) if qualities else 0.0

    # Histogram buckets: 0-19, 20-39, 40-59, 60-79, 80-100
    buckets = {"0-19": 0, "20-39": 0, "40-59": 0, "60-79": 0, "80-100": 0}
    for q in qualities:
        if q < 20:
            buckets["0-19"] += 1
        elif q < 40:
            buckets["20-39"] += 1
        elif q < 60:
            buckets["40-59"] += 1
        elif q < 80:
            buckets["60-79"] += 1
        else:
            buckets["80-100"] += 1

    # Top 10 by quality
    handler_scores.sort(key=lambda x: x[1], reverse=True)
    top = [{"handler": h, "quality": q} for h, q in handler_scores[:10]]

    return {
        "total_handlers": len(results),
        "avg_quality": round(avg_q, 1),
        "total_vars": total_vars,
        "total_consts": total_consts,
        "quality_distribution": buckets,
        "top_handlers": top,
        "error_count": error_count,
        "provider": report.get("provider", "unknown"),
    }


def print_decompilation_report(session):
    """Print a human-readable summary to the IDA output window."""
    stats = get_decompilation_stats(session)

    msg("=" * 60)
    msg("LLM Semantic Decompilation Report")
    msg("=" * 60)
    msg(f"  Provider:   {stats['provider']}")
    msg(f"  Handlers:   {stats['total_handlers']}")
    msg(f"  Errors:     {stats['error_count']}")
    msg(f"  Avg Quality: {stats['avg_quality']}/100")
    msg(f"  Vars Renamed:  {stats['total_vars']}")
    msg(f"  Constants ID'd: {stats['total_consts']}")
    msg("")
    msg("  Quality Distribution:")
    for bucket, count in stats["quality_distribution"].items():
        bar = "#" * min(count, 50)
        msg(f"    {bucket:>6s}: {count:4d} {bar}")
    msg("")
    if stats["top_handlers"]:
        msg("  Top Handlers by Quality:")
        for entry in stats["top_handlers"]:
            msg(f"    {entry['quality']:3d}  {entry['handler']}")
    msg("=" * 60)


# ===================================================================
# Re-decompile a specific handler (convenience)
# ===================================================================

def redecompile_handler(session, handler_name, apply_to_idb_flag=False):
    """Force re-decompile a single handler by TC name.

    Looks up the handler EA from the opcodes table, then runs the
    single-function decompiler with force semantics.

    Returns the result dict, or None.
    """
    db = session.db
    row = db.fetchone(
        "SELECT handler_ea FROM opcodes WHERE tc_name = ?", (handler_name,)
    )
    if not row or not row["handler_ea"]:
        msg_error(f"Handler '{handler_name}' not found in opcodes table")
        return None

    ea = row["handler_ea"]
    result = semantically_decompile_function(
        session, ea, apply_to_idb_flag=apply_to_idb_flag
    )

    if result and not result.get("error"):
        # Update stored results
        report = get_semantic_decompilation(session)
        report.setdefault("results", {})[handler_name] = result
        db.kv_set(KV_KEY, report)
        db.commit()
        msg_info(f"Re-decompiled '{handler_name}' — "
                 f"quality={result['quality_score']}")

    return result


# ===================================================================
# Batch subset: decompile by game system
# ===================================================================

def semantically_decompile_system(session, system_keyword,
                                   force=False,
                                   apply_to_idb_flag=False,
                                   rate_limit=None):
    """Decompile all handlers matching a game system keyword.

    For example, ``system_keyword="HOUSING"`` will process all CMSG
    handlers whose tc_name contains "HOUSING".

    Returns number of handlers processed.
    """
    db = session.db
    keyword = f"%{system_keyword.upper()}%"
    handlers = db.fetchall(
        "SELECT * FROM opcodes WHERE direction = 'CMSG' "
        "AND handler_ea IS NOT NULL AND UPPER(tc_name) LIKE ? "
        "ORDER BY internal_index",
        (keyword,)
    )

    if not handlers:
        msg_warn(f"No CMSG handlers matching '{system_keyword}'")
        return 0

    msg_info(f"Semantic decompiling {len(handlers)} handlers "
             f"matching '{system_keyword}'")

    if rate_limit is None:
        llm_cfg = session.cfg.get("llm") or {}
        rate_limit = float(llm_cfg.get("rate_limit", _DEFAULT_RATE_LIMIT_SECONDS))

    existing = db.kv_get(KV_KEY) or {}
    existing_results = existing.get("results", {})

    llm = LLMClient(session)
    processed = 0
    total_vars = 0
    total_consts = 0
    t0 = time.time()

    for i, row in enumerate(handlers):
        handler_ea = row["handler_ea"]
        tc_name = row["tc_name"] or f"handler_{row['internal_index']:X}"

        if not force and tc_name in existing_results:
            prev = existing_results[tc_name]
            if prev.get("clean_cpp") and prev.get("quality_score", 0) > 0:
                continue

        msg(f"  [{i + 1}/{len(handlers)}] {tc_name} at {ea_str(handler_ea)}")

        result = semantically_decompile_function(
            session, handler_ea,
            apply_to_idb_flag=apply_to_idb_flag,
            rate_limit=rate_limit,
        )

        if result and not result.get("error"):
            processed += 1
            total_vars += len(result.get("variable_map", {}))
            total_consts += len(result.get("constants_identified", {}))
            existing_results[tc_name] = result
        elif result:
            existing_results[tc_name] = result

    # Save
    _save_results(db, existing_results, processed, total_vars,
                  total_consts, llm, t0)

    msg_info(f"System '{system_keyword}': processed {processed} handlers "
             f"in {time.time() - t0:.1f}s")
    return processed


# ===================================================================
# Compare decompilation with TC source
# ===================================================================

def compare_with_tc_source(session, handler_name):
    """Load both the LLM decompilation and TC source for a handler,
    returning them side-by-side for manual review.

    Returns a dict with keys: handler, llm_cpp, tc_cpp, diff_notes.
    """
    result = get_handler_decompilation(session, handler_name)
    if not result:
        msg_warn(f"No decompilation stored for '{handler_name}'")
        return None

    tc_source = _find_tc_source(session, handler_name)

    return {
        "handler": handler_name,
        "llm_cpp": result.get("clean_cpp", ""),
        "tc_cpp": tc_source or "(TC source not found)",
        "quality_score": result.get("quality_score", 0),
        "variable_map": result.get("variable_map", {}),
        "constants_identified": result.get("constants_identified", {}),
    }


# ===================================================================
# Validate LLM connectivity
# ===================================================================

def test_llm_connection(session):
    """Send a trivial prompt to verify LLM connectivity.

    Returns (True, provider_label) on success or (False, error) on failure.
    """
    llm = LLMClient(session)
    msg_info(f"Testing LLM connection to {llm.provider_label()}...")

    response, error = llm.chat(
        "You are a test assistant.",
        "Reply with exactly: OK"
    )

    if error:
        msg_error(f"LLM connection test FAILED: {error}")
        return False, error

    msg_info(f"LLM connection test OK — got {len(response)} chars")
    return True, llm.provider_label()
