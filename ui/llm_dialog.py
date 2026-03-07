"""
LLM Provider Selection and Quick-Run Dialog

Provides:
  1. A scrollable chooser to discover and select LLM providers/models
     (auto-detects local Ollama, LM Studio, Claude CLI, API keys)
  2. A quick-run dialog to execute an LLM task immediately with the
     selected model (LLM Semantic Decompiler or Handler Scaffolding)
"""

import threading

import ida_kernwin
import idaapi

from tc_wow_analyzer.core.utils import msg, msg_info, msg_warn, msg_error


# ---------------------------------------------------------------------------
#  Provider / model discovery chooser
# ---------------------------------------------------------------------------

class LLMModelChooser(ida_kernwin.Choose):
    """Scrollable list of discovered LLM providers and their models.

    Auto-discovers Ollama, LM Studio, Claude CLI, OpenAI/Anthropic API.
    User selects one row = one provider+model combination.
    """

    def __init__(self, providers, current_provider="", current_model=""):
        super().__init__(
            "TC WoW Analyzer — Select LLM Model",
            [
                ["Provider", 24],
                ["Model", 40],
                ["Status", 12],
            ],
            flags=ida_kernwin.Choose.CH_MODAL,
            width=85,
            height=20,
        )
        self._items = []
        self._default_sel = 0

        row = 0
        for prov in providers:
            status = "Ready" if prov["available"] else "Unavailable"
            if prov["available"] and prov["models"]:
                for model in prov["models"]:
                    self._items.append([prov["name"], model, status])
                    if (prov["provider"] == current_provider
                            and model == current_model):
                        self._default_sel = row
                    row += 1
            else:
                self._items.append([prov["name"], "(none)", status])
                row += 1

        self._providers = providers

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n]

    def OnGetDefaultSelection(self):
        return [self._default_sel]

    def get_selection(self, sel_index):
        """Map a selected row index back to (provider_id, model_name)."""
        if sel_index < 0 or sel_index >= len(self._items):
            return None, None
        row = self._items[sel_index]
        display_name = row[0]
        model = row[1]
        if model == "(none)":
            return None, None
        for prov in self._providers:
            if prov["name"] == display_name and model in prov["models"]:
                return prov["provider"], model
        return None, None


def show_llm_selector(session):
    """Show the LLM model selector dialog.

    Discovers all providers, lets the user pick one, saves the choice.
    Returns (provider_id, model_name) or (None, None) if cancelled.
    """
    if not session.db:
        msg_error("No database loaded")
        return None, None

    msg_info("Discovering LLM providers...")

    from tc_wow_analyzer.core.llm_provider import (
        discover_providers, LLMConfig
    )

    providers = discover_providers()

    # Log discovery results
    for p in providers:
        status = "available" if p["available"] else "not found"
        n_models = len(p["models"])
        msg(f"  {p['name']}: {status} ({n_models} models)")

    # Load current selection for pre-selecting
    config = LLMConfig.load(session.db)

    chooser = LLMModelChooser(
        providers,
        current_provider=config.selected_provider,
        current_model=config.selected_model,
    )
    sel = chooser.Show(modal=True)

    if sel is None or sel == -1:
        return None, None

    # sel is a list for CH_MULTI, int for single-select
    idx = sel[0] if isinstance(sel, list) else sel
    provider_id, model_name = chooser.get_selection(idx)

    if not provider_id:
        msg_warn("No valid model selected")
        return None, None

    # Save selection
    config.selected_provider = provider_id
    config.selected_model = model_name
    config.save(session.db)

    msg_info(f"LLM provider set to: {provider_id} / {model_name}")
    return provider_id, model_name


# ---------------------------------------------------------------------------
#  Quick-run LLM task dialog
# ---------------------------------------------------------------------------

_LLM_TASKS = [
    ("llm_semantic_decompiler", "LLM Semantic Decompiler",
     "Auto-name and annotate handler functions using LLM analysis"),
    ("handler_scaffolding", "Handler Scaffolding Generator",
     "Generate TrinityCore C++ handler code from decompiled functions"),
]


class LLMTaskChooser(ida_kernwin.Choose):
    """Pick an LLM task to run immediately."""

    def __init__(self, current_provider, current_model):
        title = (f"TC WoW — Run LLM Task  [{current_provider}: {current_model}]"
                 if current_provider else "TC WoW — Run LLM Task  [No model selected]")
        super().__init__(
            title,
            [
                ["Task", 32],
                ["Description", 55],
            ],
            flags=ida_kernwin.Choose.CH_MODAL,
            width=95,
            height=10,
        )
        self._items = [[label, desc] for _, label, desc in _LLM_TASKS]

    def OnGetSize(self):
        return len(self._items)

    def OnGetLine(self, n):
        return self._items[n]


def show_llm_run(session):
    """Show LLM task quick-run: select model if needed, then pick a task.

    This is the main entry point for "run an LLM task now" from the menu.
    """
    if not session.db:
        msg_error("No database loaded")
        return

    from tc_wow_analyzer.core.llm_provider import LLMConfig

    config = LLMConfig.load(session.db)

    # If no model selected yet, open the selector first
    if not config.selected_provider or not config.selected_model:
        provider_id, model_name = show_llm_selector(session)
        if not provider_id:
            return
        config = LLMConfig.load(session.db)

    # Show current model and let user pick a task
    chooser = LLMTaskChooser(config.selected_provider, config.selected_model)
    sel = chooser.Show(modal=True)

    if sel is None or sel == -1:
        return

    idx = sel[0] if isinstance(sel, list) else sel
    if idx < 0 or idx >= len(_LLM_TASKS):
        return

    task_key, task_label, _ = _LLM_TASKS[idx]

    # Confirm
    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        f"Run '{task_label}' now?\n\n"
        f"Provider: {config.selected_provider}\n"
        f"Model: {config.selected_model}\n\n"
        f"This may take a while depending on the number of handlers."
    )
    if answer != ida_kernwin.ASKBTN_YES:
        return

    msg_info(f"Starting LLM task: {task_label}")
    msg_info(f"Using: {config.selected_provider} / {config.selected_model}")

    # Run the task
    try:
        from tc_wow_analyzer.ui.settings_dialog import _run_single_task
        count = _run_single_task(session, task_key)
        msg_info(f"LLM task complete: {count} items processed")
    except Exception as e:
        msg_error(f"LLM task failed: {e}")
        import traceback
        traceback.print_exc()
