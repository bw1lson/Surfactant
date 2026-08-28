# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
"""Surfactant plugin that uses Binary Ninja for control-flow graph extraction.

This plugin is intentionally scoped to the one thing Binary Ninja does *better*
than angr: high-fidelity function recovery and the per-function control-flow
graph (basic blocks + edges). To stay lightweight it loads the binary in Binary
Ninja's ``controlFlow`` analysis mode, which recovers functions and CFGs without
running the far more expensive data-flow / IL / decompilation passes. It
deliberately does **not** duplicate the loader/symbol/dependency work owned by
the ``angr_expanded`` plugin, so the two produce complementary (not overlapping)
records on the same binary.

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
_SETTINGS_CONTROL_FLOW_GRAPH = "enable_control_flow_graph"
_SETTINGS_DATA_FLOW = "enable_data_flow"
_SETTINGS_ANALYSIS_MODE = "analysis_mode"
_SETTINGS_MAX_FUNCTIONS = "max_functions"
_SETTINGS_MIN_BASIC_BLOCKS = "min_basic_blocks"
_SETTINGS_EXCLUDE_LIBRARY = "exclude_library_functions"

# Cap on how many per-function records are emitted so a single large binary
# (e.g. a statically-linked busybox with thousands of functions) cannot bloat
# the SBOM without bound. Aggregate statistics are always computed over *all*
# functions regardless of this cap.
_DEFAULT_MAX_FUNCTIONS = 5000

# Minimum basic-block count for a function to be emitted in the CFG ``functions``
# list. A single-block function has no control flow worth serializing, and such
# stubs (PLT thunks, trivial wrappers) otherwise dominate the output. They are
# still counted in the aggregate stats. Set to 1 to emit every function.
_DEFAULT_MIN_BASIC_BLOCKS = 2

# GCC/Clang emit helper "clones" — cold-path splits and interprocedural
# specializations — whose standalone CFG carries little analytic value and which
# heavily inflate the output. They are excluded from the emitted ``functions``
# list (still counted in aggregate stats). Matched as substrings of the name.
_CLONE_MARKERS = (".cold", ".isra", ".constprop", ".part")

# C++ runtime/library namespaces whose functions are rarely the analysis target
# and which dominate the CFG of any C++ binary. When library exclusion is on
# (default), functions whose name starts with one of these markers are dropped
# from the emitted ``functions`` list (still counted in aggregate stats). Both
# Itanium-mangled prefixes (e.g. ``_ZNSt`` for ``std::``) and demangled
# ``namespace::`` prefixes are matched so it works regardless of BN's naming.
_DEFAULT_LIBRARY_MARKERS = (
    "_ZNSt",  # std:: (nested)
    "_ZSt",  # std:: (free function)
    "_ZNKSt",  # std:: (const method)
    "_ZN9__gnu_cxx",  # __gnu_cxx::
    "_ZN3fmt",  # fmt::
    "_ZN6spdlog",  # spdlog::
    "_ZN7cxxopts",  # cxxopts::
    "_ZN8nlohmann",  # nlohmann::
    "std::",
    "__gnu_cxx::",
    "fmt::",
    "spdlog::",
    "cxxopts::",
    "nlohmann::",
)

# How far back the SSA def-use walk will chase an argument's provenance before
# giving up. Keeps taint tracing bounded on pathological data-flow graphs.
_MAX_TAINT_DEPTH = 12

# MLIL SSA operations that represent a call/branch-to-callee. Provenance and sink
# detection only look at these statement-level operations.
_CALL_OPS = frozenset(
    {
        "MLIL_CALL_SSA",
        "MLIL_CALL_UNTYPED_SSA",
        "MLIL_TAILCALL_SSA",
        "MLIL_TAILCALL_UNTYPED_SSA",
        "MLIL_SYSCALL_SSA",
    }
)

# Dangerous/interesting call targets ("sinks") mapped to a coarse category the
# downstream POI/exploit-pattern tool can key off of.
_SINKS: dict[str, str] = {
    # Unbounded string/memory copies -> buffer overflow surface.
    "strcpy": "bufferCopy",
    "stpcpy": "bufferCopy",
    "strcat": "bufferCopy",
    "gets": "unboundedInput",
    "sprintf": "format",
    "vsprintf": "format",
    # Bounded variants -> still POIs when the bound is attacker-derived.
    "strncpy": "boundedCopy",
    "strncat": "boundedCopy",
    "snprintf": "boundedFormat",
    "vsnprintf": "boundedFormat",
    # Raw memory ops -> overflow when size is dynamic.
    "memcpy": "memoryCopy",
    "memmove": "memoryCopy",
    "bcopy": "memoryCopy",
    "memset": "memoryWrite",
    # Format functions -> uncontrolled-format-string surface.
    "printf": "format",
    "fprintf": "format",
    "vprintf": "format",
    "vfprintf": "format",
    "syslog": "format",
    "scanf": "format",
    "sscanf": "format",
    "fscanf": "format",
    # Command / process execution.
    "system": "commandExec",
    "popen": "commandExec",
    "execl": "commandExec",
    "execlp": "commandExec",
    "execle": "commandExec",
    "execv": "commandExec",
    "execvp": "commandExec",
    "execvpe": "commandExec",
    "execve": "commandExec",
    "CreateProcessA": "commandExec",
    "CreateProcessW": "commandExec",
    "WinExec": "commandExec",
    "ShellExecuteA": "commandExec",
    "ShellExecuteW": "commandExec",
    # Allocation -> integer-overflow / heap-overflow surface when size is dynamic.
    "malloc": "allocation",
    "calloc": "allocation",
    "realloc": "allocation",
    "alloca": "allocation",
    "valloc": "allocation",
}

# Untrusted-input producers. When a sink argument's provenance traces back to one
# of these (or to a function parameter), it is flagged ``attackerControlled``.
_SOURCES = frozenset(
    {
        "recv",
        "recvfrom",
        "recvmsg",
        "read",
        "pread",
        "fread",
        "fgets",
        "gets",
        "getline",
        "getenv",
        "scanf",
        "sscanf",
        "fscanf",
        "accept",
        "ReadFile",
        "InternetReadFile",
    }
)

# Argument index carrying the *format string* for each variadic format function.
# A non-constant value there is an uncontrolled-format-string POI.
_FORMAT_ARG_INDEX: dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "scanf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "sprintf": 1,
    "vsprintf": 1,
    "sscanf": 1,
    "fscanf": 1,
    "syslog": 1,
    "snprintf": 2,
    "vsnprintf": 2,
}

# Argument index carrying the *size/length* for copy/alloc sinks. A non-constant
# value there is an overflow / integer-overflow POI.
_SIZE_ARG_INDEX: dict[str, int] = {
    "memcpy": 2,
    "memmove": 2,
    "memset": 2,
    "bcopy": 2,
    "strncpy": 2,
    "strncat": 2,
    "snprintf": 1,
    "vsnprintf": 1,
    "malloc": 0,
    "calloc": 1,
    "realloc": 1,
    "alloca": 0,
    "valloc": 0,
}


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


def _get_str_setting(key: str, default: str) -> str:
    """Read a string plugin setting, never raising on lookup failure."""
    try:
        value = ConfigManager().get(_SETTINGS_SECTION, key, default)
        return str(value) if value else default
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


def _open_view(bn: "bn", path: str, analysis_mode: str = "controlFlow") -> "Any | None":
    """Open an analyzed BinaryView for ``path`` (headless) at ``analysis_mode``.

    ``controlFlow`` (default) recovers only functions and basic blocks, which is
    all the CFG extraction needs. Data-flow / points-of-interest extraction needs
    MLIL SSA, so it raises the mode (``intermediate`` or ``full``) to run the
    variable/type and value-set analyses that resolve call arguments and def-use
    chains. Heavier modes are strictly opt-in.
    """
    try:
        view = bn.load(path, options={"analysis.mode": analysis_mode})
    except Exception as e:  # noqa: BLE001 - loading untrusted binaries can raise anything
        logger.info(f"binaryninja_info could not load {path}: {e}")
        return None
    if view is None:
        return None
    try:
        # ``load`` normally runs analysis already; this is a cheap no-op if so and
        # guarantees the CFG / IL are populated before we read them.
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


def _basic_block_record(block: "Any") -> dict[str, Any]:
    """Build a structure-only record for one basic block (no disassembly text)."""
    edges: list[dict[str, str]] = []
    for edge in getattr(block, "outgoing_edges", []):
        target = getattr(edge, "target", None)
        if target is None:
            continue
        edges.append(
            {
                "target": hex(target.start),
                "type": getattr(edge.type, "name", str(edge.type)),
            }
        )
    return {
        "start": hex(block.start),
        "end": hex(block.end),
        "instructionCount": getattr(block, "instruction_count", 0),
        "edges": edges,
    }


def _iter_control_flow(
    view: "Any", limit: int, min_basic_blocks: int, library_markers: tuple = ()
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Single pass over functions: build a filtered CFG list + full-corpus stats.

    Returns ``(functions, stats)``. ``functions`` holds compact per-function
    control-flow records (basic blocks + edges), excluding thunks, functions
    with fewer than ``min_basic_blocks`` blocks (which carry no control flow),
    compiler-generated clones, and — when ``library_markers`` is non-empty —
    functions whose name starts with a C++ runtime/library marker. Records are
    capped at ``limit``. ``stats`` aggregates over *every* recovered function
    regardless of those filters.
    """
    functions: list[dict[str, Any]] = []
    total_functions = 0
    total_basic_blocks = 0
    total_instructions = 0
    thunk_count = 0
    capped = False

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

        # Drop analytically-empty or off-target records to cut bloat: thunks
        # (pure forwarders), compiler-generated clones, functions with no real
        # control flow, and — when enabled — C++ runtime/library functions. All
        # are still counted in the aggregate stats above.
        name = func.name
        if (
            is_thunk
            or bb_count < min_basic_blocks
            or any(marker in name for marker in _CLONE_MARKERS)
            or any(name.startswith(prefix) for prefix in library_markers)
        ):
            continue
        if len(functions) >= limit:
            capped = True
            continue

        functions.append(
            {
                "name": func.name,
                "address": hex(func.start),
                "basicBlockCount": bb_count,
                "instructionCount": insn_count,
                "isThunk": is_thunk,
                "basicBlocks": [_basic_block_record(block) for block in basic_blocks],
            }
        )

    stats = {
        "functionCount": total_functions,
        "basicBlockCount": total_basic_blocks,
        "instructionCount": total_instructions,
        "thunkCount": thunk_count,
        "emittedFunctionCount": len(functions),
        "controlFlowTruncated": capped,
    }
    return functions, stats


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


# --------------------------------------------------------------------------- #
# Data-flow / points-of-interest extraction (opt-in, needs MLIL SSA).
#
# Binary Ninja has no single "data-flow graph" object: the DFG *is* the SSA
# def-use chains in the IL. These helpers walk those chains backward from each
# dangerous call ("sink") argument to classify its provenance and decide whether
# it is attacker-influenced (traces back to an untrusted source or a function
# parameter). That reachability signal is what lets a downstream tool narrow a
# huge call list down to the handful of exploitable points of interest.
# --------------------------------------------------------------------------- #


def _base_name(name: "str | None") -> "str | None":
    """Strip ABI/import decorations (``strcpy@plt`` -> ``strcpy``)."""
    if not name:
        return name
    return name.split("@")[0]


def _callee_name(view: "Any", dest_expr: "Any") -> "str | None":
    """Resolve a (direct) call target expression to a symbol/function name.

    Returns None for indirect calls (target is not a resolvable constant), which
    the caller records separately as an indirect-call POI.
    """
    if dest_expr is None:
        return None
    try:
        value = dest_expr.value
        value_type = getattr(getattr(value, "type", None), "name", "")
        if value_type not in ("ConstantValue", "ConstantPointerValue", "ImportedAddressValue"):
            return None
        addr = getattr(value, "value", None)
        if addr is None:
            return None
        symbol = view.get_symbol_at(addr)
        if symbol is not None:
            return getattr(symbol, "short_name", None) or symbol.name
        func = view.get_function_at(addr)
        if func is not None:
            return func.name
    except Exception:  # noqa: BLE001 - value/symbol resolution can raise on odd inputs
        return None
    return None


def _describe_constant(view: "Any", expr: "Any") -> "tuple[str, str] | None":
    """If ``expr`` resolves to a constant, return ``(kind, value)`` else None.

    ``kind`` is ``"string"`` when the constant points at readable data, otherwise
    ``"constant"``. This is the value-set-analysis signal (constant propagation).
    """
    try:
        value = expr.value
    except Exception:  # noqa: BLE001 - some expressions have no value
        return None
    value_type = getattr(getattr(value, "type", None), "name", "")
    if value_type not in ("ConstantValue", "ConstantPointerValue", "ImportedAddressValue"):
        return None
    raw = getattr(value, "value", None)
    if not isinstance(raw, int):
        return None
    try:
        string_ref = view.get_ascii_string_at(raw, 1)
    except Exception:  # noqa: BLE001 - address may be unreadable
        string_ref = None
    if string_ref is not None:
        text = getattr(string_ref, "value", None)
        if text:
            return ("string", text[:200])
    return ("constant", hex(raw & 0xFFFFFFFFFFFFFFFF))


def _is_parameter(mlil_ssa: "Any", var: "Any") -> bool:
    """Return True if ``var`` is one of the enclosing function's parameters."""
    try:
        params = mlil_ssa.source_function.parameter_vars
    except Exception:  # noqa: BLE001 - parameter recovery may be unavailable
        return False
    try:
        return any(var == p for p in params)
    except Exception:  # noqa: BLE001 - Variable comparison can raise on odd types
        return False


def _arg_provenance(
    view: "Any", mlil_ssa: "Any", expr: "Any", depth: int, seen: set
) -> dict[str, Any]:
    """Classify where an argument value comes from via a bounded backward SSA walk.

    Returns ``{"provenance", "value", "tainted", "taintSource"}``. ``tainted`` is
    True when the value derives from an untrusted source call or a function
    parameter — i.e. it is (transitively) attacker-influenced.
    """
    result: dict[str, Any] = {
        "provenance": "unknown",
        "value": None,
        "tainted": False,
        "taintSource": None,
    }
    if expr is None or depth <= 0:
        return result

    # 1. Constant / string / global (value-set analysis).
    described = _describe_constant(view, expr)
    if described is not None:
        result["provenance"], result["value"] = described
        return result

    op = getattr(getattr(expr, "operation", None), "name", "")

    # 2. A variable use: chase its SSA definition.
    if op in ("MLIL_VAR_SSA", "MLIL_VAR_SSA_FIELD", "MLIL_VAR_ALIASED"):
        ssa_var = getattr(expr, "src", None)
        if ssa_var is None:
            return result
        key = (
            getattr(getattr(ssa_var, "var", None), "identifier", id(ssa_var)),
            getattr(ssa_var, "version", None),
        )
        if key in seen:
            result["provenance"] = "cyclic"
            return result
        seen.add(key)

        try:
            definition = mlil_ssa.get_ssa_var_definition(ssa_var)
        except Exception:  # noqa: BLE001 - def lookup can fail on partial analysis
            definition = None

        if definition is None:
            # No definition in this function => a function input (parameter) or
            # an uninitialized/global-backed value.
            var = getattr(ssa_var, "var", None)
            if var is not None and _is_parameter(mlil_ssa, var):
                result["provenance"] = "functionParameter"
                result["tainted"] = True
                result["taintSource"] = f"param:{getattr(var, 'name', '?')}"
            else:
                result["provenance"] = "uninitialized"
            return result

        def_op = getattr(getattr(definition, "operation", None), "name", "")
        if def_op in _CALL_OPS:
            callee = _base_name(_callee_name(view, getattr(definition, "dest", None)))
            if callee and callee in _SOURCES:
                result["provenance"] = "sourceOutput"
                result["tainted"] = True
                result["taintSource"] = callee
            else:
                result["provenance"] = "callResult"
            return result

        src_expr = getattr(definition, "src", None)
        if src_expr is not None:
            return _arg_provenance(view, mlil_ssa, src_expr, depth - 1, seen)
        result["provenance"] = "defined"
        return result

    # 3. Pointer dereference: value read from memory (buffer contents).
    if op in ("MLIL_LOAD_SSA", "MLIL_LOAD"):
        addr_expr = getattr(expr, "src", None)
        sub = _arg_provenance(view, mlil_ssa, addr_expr, depth - 1, seen)
        result["provenance"] = "memoryLoad"
        result["tainted"] = sub["tainted"]
        result["taintSource"] = sub["taintSource"]
        return result

    # 4. Arithmetic / composite: propagate taint from any operand.
    operands = getattr(expr, "operands", None) or []
    tainted = False
    taint_source = None
    for sub_expr in operands:
        if not hasattr(sub_expr, "operation"):
            continue
        sub = _arg_provenance(view, mlil_ssa, sub_expr, depth - 1, seen)
        if sub["tainted"]:
            tainted = True
            taint_source = taint_source or sub["taintSource"]
    result["provenance"] = "computed"
    result["tainted"] = tainted
    result["taintSource"] = taint_source
    return result


def _collect_points_of_interest(view: "Any", limit: int) -> dict[str, Any]:
    """Extract sink/source/indirect/format POIs with data-flow taint reachability.

    Walks MLIL SSA per function (up to ``limit`` functions), locating calls to
    known sinks, classifying each argument's provenance through the SSA def-use
    graph, and flagging arguments that are (transitively) attacker-controlled.
    """
    sink_sites: list[dict[str, Any]] = []
    source_sites: list[dict[str, Any]] = []
    indirect_calls: list[dict[str, Any]] = []
    format_pois: list[dict[str, Any]] = []
    analyzed = 0
    truncated = False

    for func in view.functions:
        if analyzed >= limit:
            truncated = True
            break
        mlil = getattr(func, "mlil", None)
        if mlil is None:
            continue
        try:
            mlil_ssa = mlil.ssa_form
        except Exception:  # noqa: BLE001 - SSA form may be unavailable
            mlil_ssa = None
        if mlil_ssa is None:
            continue
        analyzed += 1

        for insn in mlil_ssa.instructions:
            op = getattr(getattr(insn, "operation", None), "name", "")
            if op not in _CALL_OPS:
                continue
            addr = hex(getattr(insn, "address", func.start))
            callee = _base_name(_callee_name(view, getattr(insn, "dest", None)))

            if callee is None:
                if "SYSCALL" not in op:
                    indirect_calls.append({"callSite": addr, "function": func.name})
                continue

            if callee in _SOURCES:
                source_sites.append(
                    {"callSite": addr, "function": func.name, "callee": callee}
                )

            category = _SINKS.get(callee)
            if category is None:
                continue

            params = list(getattr(insn, "params", None) or [])
            arg_records: list[dict[str, Any]] = []
            attacker_controlled = False
            for idx, param in enumerate(params[:8]):
                prov = _arg_provenance(view, mlil_ssa, param, _MAX_TAINT_DEPTH, set())
                arg_records.append({"index": idx, **prov})
                attacker_controlled = attacker_controlled or prov["tainted"]

            record: dict[str, Any] = {
                "callSite": addr,
                "function": func.name,
                "callee": callee,
                "category": category,
                "attackerControlled": attacker_controlled,
                "arguments": arg_records,
            }

            size_idx = _SIZE_ARG_INDEX.get(callee)
            if size_idx is not None and size_idx < len(arg_records):
                size_arg = arg_records[size_idx]
                record["dynamicSize"] = size_arg["provenance"] != "constant"

            sink_sites.append(record)

            fmt_idx = _FORMAT_ARG_INDEX.get(callee)
            if fmt_idx is not None and fmt_idx < len(arg_records):
                fmt_arg = arg_records[fmt_idx]
                if fmt_arg["provenance"] not in ("string", "constant"):
                    format_pois.append(
                        {
                            "callSite": addr,
                            "function": func.name,
                            "callee": callee,
                            "formatArgProvenance": fmt_arg["provenance"],
                            "attackerControlled": fmt_arg["tainted"],
                        }
                    )

    return {
        "sinkCallSites": sink_sites,
        "sourceCallSites": source_sites,
        "indirectCalls": indirect_calls,
        "uncontrolledFormatStrings": format_pois,
        "attackerControlledSinkCount": sum(
            1 for s in sink_sites if s["attackerControlled"]
        ),
        "pointsOfInterestTruncated": truncated,
    }


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

    # Data-flow / POI extraction needs MLIL SSA, so it forces a heavier analysis
    # mode. CFG-only extraction stays on the cheap ``controlFlow`` mode. An
    # explicit ``analysis_mode`` setting overrides the auto-selected default.
    data_flow_enabled = _get_bool_setting(_SETTINGS_DATA_FLOW, False)
    default_mode = "full" if data_flow_enabled else "controlFlow"
    analysis_mode = _get_str_setting(_SETTINGS_ANALYSIS_MODE, default_mode)

    view = _open_view(bn, path.as_posix(), analysis_mode)
    if view is None:
        return None

    max_functions = _get_int_setting(_SETTINGS_MAX_FUNCTIONS, _DEFAULT_MAX_FUNCTIONS)
    min_basic_blocks = _get_int_setting(_SETTINGS_MIN_BASIC_BLOCKS, _DEFAULT_MIN_BASIC_BLOCKS)
    library_markers = (
        _DEFAULT_LIBRARY_MARKERS
        if _get_bool_setting(_SETTINGS_EXCLUDE_LIBRARY, True)
        else ()
    )
    metadata: dict[str, Any] = {}
    try:
        metadata.update(_collect_header(bn, view))

        functions, stats = _iter_control_flow(
            view, max_functions, min_basic_blocks, library_markers
        )
        metadata.update(stats)

        if _get_bool_setting(_SETTINGS_CONTROL_FLOW_GRAPH, True):
            metadata["functions"] = functions
        if _get_bool_setting(_SETTINGS_CALL_GRAPH, False):
            metadata["callGraph"] = _collect_call_graph(view)
        if data_flow_enabled:
            metadata["pointsOfInterest"] = _collect_points_of_interest(view, max_functions)
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
