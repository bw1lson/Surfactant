# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
"""Surfactant plugin that uses Binary Ninja for structural code analysis.

This plugin is intentionally scoped to the things Binary Ninja does *better* than
angr: high-fidelity function recovery, the inter-procedural call graph, typed
function prototypes recovered by the decompiler, and cross-reference (xref) based
detection of notable/dangerous API usage. It deliberately does **not** duplicate
the loader/symbol/dependency work owned by the ``angr_expanded`` plugin, so the
two produce complementary (not overlapping) records on the same binary.

The metadata is grouped under the ``binaryNinja`` key on each software entry.

Because the Binary Ninja Python API usually lives outside ``site-packages`` and
requires a license, it is imported lazily. If it cannot be imported the plugin
registers but simply skips analysis (logging a warning), so SBOM generation is
never blocked by a missing Binary Ninja install.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime here
    import binaryninja as bn

# Top-level key the metadata object is stored under in the software entry.
_METADATA_KEY = "binaryNinja"

# Settings section and keys (read via Surfactant's ConfigManager).
_SETTINGS_SECTION = "binary_ninja"
_SETTINGS_CALL_GRAPH = "enable_call_graph"
_SETTINGS_DECOMPILATION = "enable_decompilation"
_SETTINGS_FUNCTION_LIST = "enable_function_list"
_SETTINGS_MAX_FUNCTIONS = "max_functions"

# Cap on how many per-function records are emitted so a single large binary
# (e.g. a statically-linked busybox with thousands of functions) cannot bloat
# the SBOM without bound. Aggregate statistics are always computed over *all*
# functions regardless of this cap.
_DEFAULT_MAX_FUNCTIONS = 5000

# Imported functions that are frequently interesting from a security/behavior
# standpoint. Binary Ninja resolves the code cross-references to each of these,
# so ``notableApiReferences`` reports *which functions actually call them* rather
# than merely whether the symbol is present.
_NOTABLE_APIS = frozenset(
    {
        "system",
        "execve",
        "execl",
        "execlp",
        "execvp",
        "popen",
        "fork",
        "socket",
        "connect",
        "bind",
        "listen",
        "recv",
        "send",
        "dlopen",
        "dlsym",
        "mmap",
        "mprotect",
        "ptrace",
        "strcpy",
        "strcat",
        "sprintf",
        "gets",
        "memcpy",
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "URLDownloadToFileA",
        "InternetOpenA",
        "WSAStartup",
    }
)


def supports_file(filetype: list[str]) -> bool:
    """Return True for executable formats Binary Ninja can load."""
    return any(t in filetype for t in ("ELF", "PE", "MACHOFAT", "MACHO"))


# ELF ``e_type`` values kept for analysis: ET_EXEC (executables) and ET_DYN
# (shared objects / PIE executables). ET_REL (relocatable objects, which is what
# Linux kernel modules ``.ko`` and ``.o`` files are) and ET_CORE are excluded so
# Binary Ninja only analyzes true loadable executables/libraries.
_ELF_ANALYZABLE_ETYPES = frozenset({2, 3})  # ET_EXEC, ET_DYN


def _is_true_executable(path: Path, filetype: list[str]) -> bool:
    """Return True only for genuine loadable binaries.

    For ELF, this reads ``e_type`` and rejects relocatable objects (``.ko``
    kernel modules, ``.o`` files) and core dumps. Non-ELF supported formats
    (PE, Mach-O) are executables/dylibs already and are allowed through.
    """
    if "ELF" not in filetype:
        return True
    try:
        with path.open("rb") as f:
            header = f.read(18)
    except OSError:
        return False
    if len(header) < 18 or header[:4] != b"\x7fELF":
        return False
    # EI_DATA (byte 5): 1 = little-endian, 2 = big-endian.
    endian = "big" if header[5] == 2 else "little"
    e_type = int.from_bytes(header[16:18], endian)
    return e_type in _ELF_ANALYZABLE_ETYPES


def _get_bool_setting(key: str, default: bool) -> bool:
    """Read a boolean plugin setting, never raising on lookup failure."""
    try:
        return bool(ConfigManager().get(_SETTINGS_SECTION, key, default))
    except Exception:  # noqa: BLE001 - config lookup must never break extraction
        return default


def _get_int_setting(key: str, default: int) -> int:
    """Read an integer plugin setting, never raising on lookup failure."""
    try:
        value = ConfigManager().get(_SETTINGS_SECTION, key, default)
        return int(value)
    except Exception:  # noqa: BLE001 - config lookup must never break extraction
        return default


def _load_binaryninja() -> "bn | None":
    """Import the Binary Ninja API lazily; return the module or None."""
    try:
        import binaryninja as bn  # noqa: PLC0415 - intentional lazy import
    except Exception as e:  # noqa: BLE001 - missing/broken install must not crash
        logger.warning(
            "binaryninja_info: Binary Ninja Python API not importable "
            f"({type(e).__name__}: {e}); skipping structural analysis"
        )
        return None
    return bn


def _open_view(bn: "bn", path: str) -> "Any | None":
    """Open a fully-analyzed BinaryView for ``path`` (headless)."""
    try:
        view = bn.load(path)
    except Exception as e:  # noqa: BLE001 - loading untrusted binaries can raise anything
        logger.info(f"binaryninja_info could not load {path}: {e}")
        return None
    if view is None:
        return None
    try:
        # ``load`` normally runs analysis already; this is a cheap no-op if so and
        # guarantees the call graph / IL are populated before we read them.
        view.update_analysis_and_wait()
    except Exception as e:  # noqa: BLE001 - analysis can fail on malformed input
        logger.warning(f"binaryninja_info analysis incomplete for {path}: {e}")
    return view


def _collect_header(bn: "bn", view: "Any") -> dict[str, Any]:
    """Collect BN-unique provenance/platform header fields.

    Loader facts that angr already owns (``arch``, ``endianness``, ``entryPoint``,
    ``objectFormat``, image base, sections, ...) are intentionally *not* repeated
    here to keep the two plugins non-redundant. ``platform`` is kept because it is
    a Binary Ninja concept that folds in the OS/ABI dimension angr does not report
    (e.g. ``linux-aarch64``).
    """
    platform = getattr(view, "platform", None)
    return {
        "coreVersion": bn.core_version(),
        "platform": getattr(platform, "name", None),
    }


def _iter_function_stats(view: "Any", limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Single pass over functions: build a capped inventory + full-corpus stats.

    Returns ``(inventory, stats)`` where ``inventory`` is at most ``limit`` compact
    per-function records and ``stats`` aggregates over *every* recovered function.
    """
    inventory: list[dict[str, Any]] = []
    total_functions = 0
    total_basic_blocks = 0
    total_instructions = 0
    thunk_count = 0

    for func in view.functions:
        total_functions += 1
        basic_blocks = func.basic_blocks
        bb_count = len(basic_blocks)
        insn_count = 0
        for block in basic_blocks:
            insn_count += getattr(block, "instruction_count", 0)
        total_basic_blocks += bb_count
        total_instructions += insn_count

        is_thunk = bool(getattr(func, "is_thunk", False))
        if is_thunk:
            thunk_count += 1

        if len(inventory) < limit:
            try:
                param_count = len(func.parameter_vars)
            except Exception:  # noqa: BLE001 - parameter recovery may be unavailable
                param_count = 0
            inventory.append(
                {
                    "name": func.name,
                    "address": hex(func.start),
                    "basicBlockCount": bb_count,
                    "instructionCount": insn_count,
                    "parameterCount": param_count,
                    "isThunk": is_thunk,
                }
            )

    stats = {
        "functionCount": total_functions,
        "basicBlockCount": total_basic_blocks,
        "instructionCount": total_instructions,
        "thunkCount": thunk_count,
        "inventoryTruncated": total_functions > len(inventory),
    }
    return inventory, stats


def _collect_call_graph(view: "Any") -> dict[str, dict[str, list[str]]]:
    """Build a per-function caller/callee map from Binary Ninja's call graph.

    Binary Ninja resolves callers/callees directly per ``Function``, so this is
    both more complete and cheaper than reconstructing it from a raw CFG.
    """
    graph: dict[str, dict[str, list[str]]] = {}
    for func in view.functions:
        callees = sorted({c.name for c in func.callees if c is not None})
        callers = sorted({c.name for c in func.callers if c is not None})
        if callees or callers:
            graph[func.name] = {"calls": callees, "calledBy": callers}
    return graph


def _collect_notable_apis(bn: "bn", view: "Any") -> dict[str, list[str]]:
    """Map each referenced notable API to the functions that call it (via xrefs)."""
    notable: dict[str, set[str]] = {}
    symbol_types = []
    for attr in ("ImportedFunctionSymbol", "ExternalSymbol", "FunctionSymbol"):
        sym_type = getattr(bn.SymbolType, attr, None)
        if sym_type is not None:
            symbol_types.append(sym_type)

    for sym_type in symbol_types:
        for symbol in view.get_symbols_of_type(sym_type):
            raw = getattr(symbol, "short_name", None) or symbol.name
            base = raw.split("@")[0] if raw else raw
            if base not in _NOTABLE_APIS:
                continue
            callers = notable.setdefault(base, set())
            try:
                refs = view.get_code_refs(symbol.address)
            except Exception:  # noqa: BLE001 - address may not be referenceable
                continue
            for ref in refs:
                ref_func = getattr(ref, "function", None)
                if ref_func is not None:
                    callers.add(ref_func.name)

    return {api: sorted(callers) for api, callers in sorted(notable.items())}


def _collect_prototypes(view: "Any", limit: int) -> list[dict[str, Any]]:
    """Collect Binary Ninja's recovered *typed* function prototypes (decompiler).

    This is the decompilation signal angr does not provide: variable/type recovery
    surfaced as a C-like prototype per function.
    """
    prototypes: list[dict[str, Any]] = []
    for func in view.functions:
        if len(prototypes) >= limit:
            break
        try:
            prototype = str(func.type)
        except Exception:  # noqa: BLE001 - type rendering can fail
            continue
        prototypes.append({"name": func.name, "prototype": prototype})
    return prototypes


@surfactant.plugin.hookimpl(specname="extract_file_info")
def binaryninja_info(
    sbom: SBOM, software: Software, filename: str, filetype: list[str]
) -> object:
    """Extract Binary Ninja structural analysis metadata for the SBOM.

    Args:
        sbom (SBOM): The SBOM the software entry belongs to.
        software (Software): The software entry the metadata will be attached to.
        filename (str): Full path to the file to analyze.
        filetype (List[str]): File type hints based on magic bytes.

    Returns:
        object: A metadata dict stored under ``binaryNinja``, or None if the file
            is unsupported or Binary Ninja could not analyze it.
    """
    if not supports_file(filetype):
        return None

    path = Path(filename)
    if not path.exists():
        logger.warning(f"binaryninja_info: file does not exist: {filename}")
        return None

    if not _is_true_executable(path, filetype):
        logger.info(
            "binaryninja_info: skipping non-executable ELF "
            f"(relocatable object / kernel module / core): {path.name}"
        )
        return None

    bn = _load_binaryninja()
    if bn is None:
        return None

    view = _open_view(bn, path.as_posix())
    if view is None:
        return None

    max_functions = _get_int_setting(_SETTINGS_MAX_FUNCTIONS, _DEFAULT_MAX_FUNCTIONS)
    metadata: dict[str, Any] = {}
    try:
        metadata.update(_collect_header(bn, view))

        inventory, stats = _iter_function_stats(view, max_functions)
        metadata.update(stats)
        metadata["notableApiReferences"] = _collect_notable_apis(bn, view)

        if _get_bool_setting(_SETTINGS_FUNCTION_LIST, True):
            metadata["functions"] = inventory
        if _get_bool_setting(_SETTINGS_CALL_GRAPH, False):
            metadata["callGraph"] = _collect_call_graph(view)
        if _get_bool_setting(_SETTINGS_DECOMPILATION, False):
            metadata["functionPrototypes"] = _collect_prototypes(view, max_functions)
    except Exception as e:  # noqa: BLE001 - keep SBOM generation resilient
        logger.warning(f"binaryninja_info partial extraction for {filename}: {e}")
    finally:
        try:
            view.file.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass

    if not metadata:
        return None

    logger.info(f"binaryninja_info extracted metadata for {path.name}")
    return {_METADATA_KEY: metadata}


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    """Short name used to enable/disable and reference this plugin."""
    return "binaryninja_info"


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    """Base name used for reading/writing this plugin's Surfactant settings."""
    return _SETTINGS_SECTION
