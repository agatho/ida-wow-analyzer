"""
Minimal fakes for the IDA modules, so plugin code that only touches the DB and
the filesystem can be exercised without IDA.

This is what makes tests/test_importers.py possible: the AutoDump importers are
pure JSON -> SQLite, but they live in a package whose imports reach into
`idaapi`, `ida_loader` and friends at module level. Install the stubs BEFORE
importing anything from tc_wow_analyzer.
"""

import sys
import types


IMAGE_BASE = 0x7FF780FD0000


def _module(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


class _Cvar:
    batch = True


def install(image_base=IMAGE_BASE, idb_path="/tmp/stub_wow_dump.bin.i64"):
    """Register stub IDA modules in sys.modules. Idempotent."""
    if "idaapi" in sys.modules and getattr(sys.modules["idaapi"], "_tc_stub", False):
        return

    idaapi = _module(
        "idaapi", _tc_stub=True, cvar=_Cvar(),
        BADADDR=0xFFFFFFFFFFFFFFFF,
        MFF_FAST=0, MFF_READ=1, MFF_WRITE=2,
        execute_sync=lambda fn, flags=0: (fn(), 1)[1],
        register_timer=lambda ms, fn: None,
        get_screen_ea=lambda: image_base,
    )

    class _plugmod:
        pass

    class _plugin:
        pass

    class _action_handler:
        def __init__(self, *a, **k):
            pass

    idaapi.plugmod_t = _plugmod
    idaapi.plugin_t = _plugin
    idaapi.action_handler_t = _action_handler
    idaapi.action_desc_t = lambda *a, **k: None
    idaapi.register_action = lambda desc: True
    idaapi.unregister_action = lambda name: True
    idaapi.attach_action_to_menu = lambda *a, **k: True
    idaapi.PLUGIN_MULTI = 1
    idaapi.PLUGIN_FIX = 2
    idaapi.PLUGIN_SKIP = 0
    idaapi.SETMENU_APP = 0

    mods = {
        "idaapi": idaapi,
        "ida_loader": _module(
            "ida_loader", PATH_TYPE_IDB=0,
            get_path=lambda kind=0: idb_path),
        "ida_ida": _module(
            "ida_ida",
            inf_get_min_ea=lambda: image_base,
            inf_is_64bit=lambda: True),
        "ida_kernwin": _module(
            "ida_kernwin", BWN_DISASM=0, BWN_PSEUDOCODE=1,
            ASKBTN_YES=1,
            get_screen_ea=lambda: image_base,
            msg=lambda text: None,
            show_wait_box=lambda text: None,
            hide_wait_box=lambda: None,
            replace_wait_box=lambda text: None,
            user_cancelled=lambda: False,
            attach_action_to_popup=lambda *a, **k: True),
        "ida_name": _module(
            "ida_name", SN_NOCHECK=0, SN_FORCE=0,
            get_name=lambda ea: "",
            set_name=lambda ea, name, flags=0: True),
        "ida_funcs": _module("ida_funcs", get_func=lambda ea: None,
                             get_next_func=lambda ea: None),
        "ida_bytes": _module(
            "ida_bytes",
            get_bytes=lambda ea, size: None,
            get_qword=lambda ea: 0,
            get_dword=lambda ea: 0),
        "ida_nalt": _module("ida_nalt",
                            get_input_file_path=lambda: "/tmp/stub_wow_dump.bin"),
        "ida_auto": _module("ida_auto",
                            auto_wait=lambda: None,
                            auto_is_ok=lambda: True),
        "ida_segment": _module("ida_segment",
                               get_segm_by_name=lambda name: None,
                               getseg=lambda ea: None),
        "ida_xref": _module("ida_xref"),
        "ida_idp": _module("ida_idp", IDB_Hooks=object),
        "ida_typeinf": _module("ida_typeinf"),
        "ida_hexrays": _module("ida_hexrays",
                               init_hexrays_plugin=lambda: False,
                               decompile=lambda ea: None,
                               install_hexrays_callback=lambda cb: None,
                               remove_hexrays_callback=lambda cb: None),
        "idautils": _module("idautils", Functions=lambda *a: iter(())),
        "idc": _module("idc",
                       get_idb_path=lambda: idb_path,
                       save_database=lambda *a, **k: None),
    }
    for name, mod in mods.items():
        sys.modules.setdefault(name, mod)
    sys.modules["idaapi"] = idaapi
