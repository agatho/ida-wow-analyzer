"""
LLM Provider abstraction layer for the TC WoW Analyzer IDA Pro plugin.

Provides a unified interface for multiple LLM backends with auto-discovery
of locally installed models. Supports Ollama, LM Studio, OpenAI API,
Anthropic API, Claude CLI (subscription), and generic OpenAI-compatible
endpoints.

Design constraints:
  - Uses only stdlib (urllib, json, subprocess) -- no pip dependencies
  - All network calls have timeouts (5s discovery, 300s completion)
  - Thread-safe: safe to call from IDA UI or background threads
  - Graceful degradation when providers are unavailable

Usage:
    from tc_wow_analyzer.core.llm_provider import (
        discover_providers, create_provider, get_or_discover_provider, LLMConfig
    )

    # Quick start -- auto-discover and use first available provider
    provider = get_or_discover_provider(session)
    answer = provider.complete("Explain this decompiled function: ...")

    # Manual configuration
    config = LLMConfig(selected_provider="ollama", selected_model="llama3:70b")
    provider = create_provider(config)
    answer = provider.complete(prompt, system_prompt="You are a reverse engineer.")
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

_DISCOVERY_TIMEOUT = 5      # seconds for probing local endpoints
_COMPLETION_TIMEOUT = 300   # seconds for LLM generation
_CLI_TIMEOUT = 300          # seconds for Claude CLI subprocess

_OLLAMA_BASE = "http://localhost:11434"
_LMSTUDIO_BASE = "http://localhost:1234"
_OPENAI_BASE = "https://api.openai.com"
_ANTHROPIC_BASE = "https://api.anthropic.com"

_OPENAI_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]
_ANTHROPIC_MODELS = ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"]

_KV_KEY = "llm_config"


# ---------------------------------------------------------------------------
#  LLMConfig -- persisted provider selection
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """Persisted LLM configuration.

    Saved to / loaded from the session KnowledgeDB ``kv_store`` table
    under the key ``llm_config``.
    """
    selected_provider: str = ""
    selected_model: str = ""
    temperature: float = 0.3
    max_tokens: int = 4096
    custom_endpoint: str = ""
    custom_api_key: str = ""

    # -- Serialization helpers ------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LLMConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    def save(self, db) -> None:
        """Persist to the KnowledgeDB kv_store."""
        db.kv_set(_KV_KEY, self.to_dict())
        db.commit()

    @classmethod
    def load(cls, db) -> "LLMConfig":
        """Load from the KnowledgeDB kv_store.  Returns defaults if absent."""
        data = db.kv_get(_KV_KEY)
        if isinstance(data, dict):
            return cls.from_dict(data)
        return cls()


# ---------------------------------------------------------------------------
#  Base provider
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """Abstract base for all LLM backends."""

    provider_id: str = ""       # e.g. "ollama", "openai"
    display_name: str = ""      # human-readable name

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        """Send *prompt* to the LLM and return the text response.

        Parameters
        ----------
        prompt : str
            The user / main prompt text.
        system_prompt : str, optional
            An optional system-level instruction prepended to the conversation.
        max_tokens : int
            Maximum tokens in the response.
        temperature : float
            Sampling temperature (0.0 = deterministic, 1.0 = creative).

        Returns
        -------
        str
            The model's text response.

        Raises
        ------
        LLMProviderError
            On any communication or generation failure.
        """

    def ensure_model_loaded(self, timeout: float = 120.0) -> bool:
        """Ensure the model is loaded and ready for inference.

        For local providers (LM Studio, Ollama), this triggers model loading
        if the model isn't already in memory.  For API providers, this is a
        no-op that returns True.

        Parameters
        ----------
        timeout : float
            Maximum seconds to wait for the model to load.

        Returns
        -------
        bool
            True if the model is ready, False if loading failed.
        """
        return True  # default: assume ready (API providers)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider_id={self.provider_id!r}>"


class LLMProviderError(RuntimeError):
    """Raised when an LLM provider call fails."""


# ---------------------------------------------------------------------------
#  HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def _http_get_json(url: str, timeout: float = _DISCOVERY_TIMEOUT,
                   headers: Optional[dict] = None) -> Any:
    """GET *url* and return parsed JSON.  Raises on any failure."""
    req = urllib.request.Request(url, method="GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(url: str, payload: dict, timeout: float = _COMPLETION_TIMEOUT,
                    headers: Optional[dict] = None) -> Any:
    """POST JSON *payload* to *url* and return parsed JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
#  OllamaProvider
# ---------------------------------------------------------------------------

class OllamaProvider(LLMProvider):
    """Ollama local inference server (http://localhost:11434)."""

    provider_id = "ollama"
    display_name = "Ollama (Local)"

    def __init__(self, model: str, base_url: str = _OLLAMA_BASE):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        url = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = _http_post_json(url, payload)
            return resp.get("response", "")
        except Exception as exc:
            raise LLMProviderError(
                f"Ollama completion failed ({self.model}): {exc}"
            ) from exc

    def ensure_model_loaded(self, timeout: float = 120.0) -> bool:
        """Send a tiny prompt to force Ollama to load the model into memory."""
        msg_info(f"Ollama: ensuring model '{self.model}' is loaded...")
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": "Hi",
            "stream": False,
            "options": {"num_predict": 1},
        }
        try:
            _http_post_json(url, payload, timeout=timeout)
            msg_info(f"Ollama: model '{self.model}' is ready")
            return True
        except Exception as exc:
            msg_error(f"Ollama: failed to load model '{self.model}': {exc}")
            return False

    @staticmethod
    def discover(base_url: str = _OLLAMA_BASE) -> List[str]:
        """Return list of available model names, or empty list on failure."""
        try:
            data = _http_get_json(f"{base_url.rstrip('/')}/api/tags")
            models = data.get("models", [])
            return [m["name"] for m in models if "name" in m]
        except Exception:
            return []


# ---------------------------------------------------------------------------
#  LMStudioProvider
# ---------------------------------------------------------------------------

class LMStudioProvider(LLMProvider):
    """LM Studio local server (OpenAI-compatible at http://localhost:1234)."""

    provider_id = "lmstudio"
    display_name = "LM Studio (Local)"

    def __init__(self, model: str, base_url: str = _LMSTUDIO_BASE):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

        try:
            resp = _http_post_json(url, payload)
            return resp["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMProviderError(
                f"LM Studio completion failed ({self.model}): {exc}"
            ) from exc

    def ensure_model_loaded(self, timeout: float = 120.0) -> bool:
        """Load the selected model in LM Studio.

        LM Studio 0.3+ supports POST /v1/models/load to explicitly load a
        model.  If that endpoint isn't available (older versions), we fall
        back to sending a tiny completion request which triggers auto-load.
        """
        msg_info(f"LM Studio: ensuring model '{self.model}' is loaded...")

        # Strategy 1: Try the explicit model load endpoint (LM Studio 0.3+)
        try:
            load_url = f"{self.base_url}/v1/models/load"
            payload = {"model": self.model}
            _http_post_json(load_url, payload, timeout=timeout)
            msg_info(f"LM Studio: model '{self.model}' loaded via /v1/models/load")
            return True
        except Exception:
            pass  # endpoint may not exist in older versions

        # Strategy 2: Send a minimal completion to trigger auto-load
        try:
            url = f"{self.base_url}/v1/chat/completions"
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": "Hi"}],
                "max_tokens": 1,
                "temperature": 0.0,
                "stream": False,
            }
            _http_post_json(url, payload, timeout=timeout)
            msg_info(f"LM Studio: model '{self.model}' is ready")
            return True
        except Exception as exc:
            msg_error(f"LM Studio: failed to load model '{self.model}': {exc}")
            return False

    @staticmethod
    def discover(base_url: str = _LMSTUDIO_BASE) -> List[str]:
        """Return list of loaded model IDs, or empty list on failure."""
        try:
            data = _http_get_json(f"{base_url.rstrip('/')}/v1/models")
            models = data.get("data", [])
            return [m["id"] for m in models if "id" in m]
        except Exception:
            return []


# ---------------------------------------------------------------------------
#  OpenAIProvider
# ---------------------------------------------------------------------------

class OpenAIProvider(LLMProvider):
    """OpenAI API (requires OPENAI_API_KEY environment variable)."""

    provider_id = "openai"
    display_name = "OpenAI API"

    def __init__(self, model: str, api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            raise LLMProviderError(
                "OpenAI API key not set. Set OPENAI_API_KEY or pass api_key."
            )

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        url = f"{_OPENAI_BASE}/v1/chat/completions"
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            resp = _http_post_json(url, payload, headers=headers)
            return resp["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMProviderError(
                f"OpenAI completion failed ({self.model}): {exc}"
            ) from exc

    @staticmethod
    def is_available() -> bool:
        return bool(os.environ.get("OPENAI_API_KEY"))


# ---------------------------------------------------------------------------
#  AnthropicAPIProvider
# ---------------------------------------------------------------------------

class AnthropicAPIProvider(LLMProvider):
    """Anthropic Messages API (requires ANTHROPIC_API_KEY environment variable)."""

    provider_id = "anthropic"
    display_name = "Anthropic API"

    _API_VERSION = "2023-06-01"

    def __init__(self, model: str, api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise LLMProviderError(
                "Anthropic API key not set. Set ANTHROPIC_API_KEY or pass api_key."
            )

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        url = f"{_ANTHROPIC_BASE}/v1/messages"
        messages: List[Dict[str, str]] = [
            {"role": "user", "content": prompt},
        ]
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self._API_VERSION,
        }

        try:
            resp = _http_post_json(url, payload, headers=headers)
            # Anthropic returns content as a list of blocks
            content_blocks = resp.get("content", [])
            texts = [
                block.get("text", "")
                for block in content_blocks
                if block.get("type") == "text"
            ]
            return "".join(texts)
        except Exception as exc:
            raise LLMProviderError(
                f"Anthropic completion failed ({self.model}): {exc}"
            ) from exc

    @staticmethod
    def is_available() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))


# ---------------------------------------------------------------------------
#  ClaudeCLIProvider
# ---------------------------------------------------------------------------

class ClaudeCLIProvider(LLMProvider):
    """Claude CLI (``claude`` binary in PATH).

    Allows Claude subscription users (not API) to use Claude from within
    IDA by shelling out to the Claude Code CLI tool.
    """

    provider_id = "claude_cli"
    display_name = "Claude CLI (Subscription)"

    def __init__(self):
        self._binary = shutil.which("claude")
        if not self._binary:
            raise LLMProviderError("Claude CLI binary not found in PATH.")

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        # The Claude CLI accepts a prompt via -p flag.
        # system_prompt is prepended to the user prompt since the CLI
        # does not have a separate system prompt flag.
        full_prompt = prompt
        if system_prompt:
            full_prompt = (
                f"<system>\n{system_prompt}\n</system>\n\n{prompt}"
            )

        cmd = [self._binary, "-p", full_prompt]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_CLI_TIMEOUT,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                raise LLMProviderError(
                    f"Claude CLI exited with code {result.returncode}: {stderr}"
                )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise LLMProviderError(
                f"Claude CLI timed out after {_CLI_TIMEOUT}s"
            )
        except FileNotFoundError:
            raise LLMProviderError("Claude CLI binary not found.")
        except Exception as exc:
            raise LLMProviderError(f"Claude CLI error: {exc}") from exc

    @staticmethod
    def is_available() -> bool:
        return shutil.which("claude") is not None


# ---------------------------------------------------------------------------
#  OpenAICompatibleProvider
# ---------------------------------------------------------------------------

class OpenAICompatibleProvider(LLMProvider):
    """Generic OpenAI-compatible API endpoint (user-configured URL).

    Works with any server that implements the ``/v1/chat/completions``
    endpoint (vLLM, text-generation-inference, LocalAI, etc.).
    """

    provider_id = "openai_compatible"
    display_name = "OpenAI-Compatible (Custom)"

    def __init__(self, base_url: str, model: str, api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = _http_post_json(url, payload, headers=headers or None)
            return resp["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMProviderError(
                f"OpenAI-compatible completion failed ({self.base_url}, "
                f"{self.model}): {exc}"
            ) from exc

    @staticmethod
    def discover(base_url: str, api_key: str = "") -> List[str]:
        """Probe the /v1/models endpoint for available model IDs."""
        try:
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            data = _http_get_json(
                f"{base_url.rstrip('/')}/v1/models",
                headers=headers or None,
            )
            models = data.get("data", [])
            return [m["id"] for m in models if "id" in m]
        except Exception:
            return []


# ---------------------------------------------------------------------------
#  Provider discovery
# ---------------------------------------------------------------------------

def discover_providers() -> List[Dict[str, Any]]:
    """Probe all known backends and return a list of provider descriptors.

    Each descriptor is a dict with keys:
        provider   -- provider id string (e.g. "ollama")
        name       -- human-readable display name
        models     -- list of available model name strings
        available  -- bool, True if the backend responded / is configured

    Discovery of local endpoints (Ollama, LM Studio) is done in parallel
    threads to avoid blocking the UI for the full timeout duration.

    Returns
    -------
    list[dict]
        One entry per known provider type, regardless of availability.
    """
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    # -- Threaded local discovery ---------------------------------------------

    def _probe_ollama():
        models = OllamaProvider.discover()
        with lock:
            results.append({
                "provider": "ollama",
                "name": "Ollama (Local)",
                "models": models,
                "available": len(models) > 0,
            })

    def _probe_lmstudio():
        models = LMStudioProvider.discover()
        with lock:
            results.append({
                "provider": "lmstudio",
                "name": "LM Studio (Local)",
                "models": models,
                "available": len(models) > 0,
            })

    threads = [
        threading.Thread(target=_probe_ollama, daemon=True),
        threading.Thread(target=_probe_lmstudio, daemon=True),
    ]
    for t in threads:
        t.start()

    # -- Non-threaded checks (env vars / PATH lookups are instant) -----------

    # Claude CLI
    cli_available = ClaudeCLIProvider.is_available()
    results.append({
        "provider": "claude_cli",
        "name": "Claude CLI (Subscription)",
        "models": ["claude-cli"],
        "available": cli_available,
    })

    # OpenAI API
    openai_available = OpenAIProvider.is_available()
    results.append({
        "provider": "openai",
        "name": "OpenAI API",
        "models": list(_OPENAI_MODELS),
        "available": openai_available,
    })

    # Anthropic API
    anthropic_available = AnthropicAPIProvider.is_available()
    results.append({
        "provider": "anthropic",
        "name": "Anthropic API",
        "models": list(_ANTHROPIC_MODELS),
        "available": anthropic_available,
    })

    # OpenAI-compatible (always present but not auto-available)
    results.append({
        "provider": "openai_compatible",
        "name": "OpenAI-Compatible (Custom)",
        "models": [],
        "available": False,
    })

    # -- Wait for local probes ------------------------------------------------

    for t in threads:
        t.join(timeout=_DISCOVERY_TIMEOUT + 1)

    # Sort: available providers first, then alphabetical
    results.sort(key=lambda r: (not r["available"], r["provider"]))

    return results


# ---------------------------------------------------------------------------
#  Factory
# ---------------------------------------------------------------------------

def create_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate an ``LLMProvider`` from the given configuration.

    Parameters
    ----------
    config : LLMConfig
        Must have ``selected_provider`` set.  ``selected_model`` is
        required for all providers except ``claude_cli``.

    Returns
    -------
    LLMProvider

    Raises
    ------
    LLMProviderError
        If the provider id is unknown or required fields are missing.
    """
    pid = config.selected_provider
    model = config.selected_model

    if pid == "ollama":
        if not model:
            raise LLMProviderError("No model selected for Ollama.")
        return OllamaProvider(model=model)

    elif pid == "lmstudio":
        if not model:
            raise LLMProviderError("No model selected for LM Studio.")
        return LMStudioProvider(model=model)

    elif pid == "openai":
        if not model:
            raise LLMProviderError("No model selected for OpenAI.")
        return OpenAIProvider(model=model)

    elif pid == "anthropic":
        if not model:
            raise LLMProviderError("No model selected for Anthropic.")
        return AnthropicAPIProvider(model=model)

    elif pid == "claude_cli":
        return ClaudeCLIProvider()

    elif pid == "openai_compatible":
        if not config.custom_endpoint:
            raise LLMProviderError(
                "No custom_endpoint configured for OpenAI-compatible provider."
            )
        if not model:
            raise LLMProviderError(
                "No model selected for OpenAI-compatible provider."
            )
        return OpenAICompatibleProvider(
            base_url=config.custom_endpoint,
            model=model,
            api_key=config.custom_api_key,
        )

    else:
        raise LLMProviderError(f"Unknown provider id: {pid!r}")


# ---------------------------------------------------------------------------
#  Convenience entry point
# ---------------------------------------------------------------------------

def get_or_discover_provider(session) -> LLMProvider:
    """Load persisted config, auto-discover if needed, return a ready provider.

    Parameters
    ----------
    session : PluginSession
        Must have a ``db`` attribute (``KnowledgeDB`` instance).

    Returns
    -------
    LLMProvider
        A configured, ready-to-use provider.

    Raises
    ------
    LLMProviderError
        If no provider could be discovered or configured.

    Behaviour
    ---------
    1. Load ``LLMConfig`` from the session database.
    2. If a provider is already selected and looks valid, create and return it.
    3. Otherwise, run ``discover_providers()`` and pick the first available.
    4. Persist the selection so subsequent calls skip discovery.
    """
    db = session.db
    config = LLMConfig.load(db)

    # Try the persisted selection first
    if config.selected_provider:
        try:
            provider = create_provider(config)
            msg_info(
                f"LLM provider: {provider.display_name} "
                f"(model: {config.selected_model})"
            )
            return provider
        except LLMProviderError as exc:
            msg_warn(
                f"Saved LLM provider unavailable ({config.selected_provider}): "
                f"{exc}. Re-discovering..."
            )

    # Auto-discover
    msg_info("Discovering available LLM providers...")
    providers = discover_providers()

    available = [p for p in providers if p["available"]]
    if not available:
        msg_error("No LLM providers found. Install Ollama, LM Studio, or "
                  "set OPENAI_API_KEY / ANTHROPIC_API_KEY / install Claude CLI.")
        raise LLMProviderError("No LLM providers available.")

    # Log what we found
    for p in providers:
        status = "available" if p["available"] else "not found"
        model_str = ", ".join(p["models"][:3])
        if len(p["models"]) > 3:
            model_str += f", ... (+{len(p['models']) - 3} more)"
        msg(f"  {p['name']}: {status}"
            + (f" [{model_str}]" if p["available"] else ""))

    # Pick the first available provider and its first model
    chosen = available[0]
    chosen_model = chosen["models"][0] if chosen["models"] else ""

    config.selected_provider = chosen["provider"]
    config.selected_model = chosen_model
    config.save(db)

    provider = create_provider(config)
    msg_info(
        f"Auto-selected LLM provider: {provider.display_name} "
        f"(model: {chosen_model})"
    )
    return provider
