# surfactantplugin-binaryninja-info

A Surfactant plugin that uses **Binary Ninja** for lightweight *control-flow
graph* extraction and embeds the results into the generated SBOM under the
`binaryNinja` metadata key.

It is designed to be **complementary** to the `angr_expanded` plugin, not
overlapping. Each tool focuses on what it does best:

| Concern | Owned by | Why |
|---------|----------|-----|
| Loader/architecture, PIC, sections | `angr_expanded` (angr/CLE) | angr's loader is fast and authoritative |
| Imported/exported symbols | `angr_expanded` | drives dependency resolution |
| Import → library resolution, `Uses` relationships | `angr_expanded` | CLE resolves providers |
| Minimum library versions (CVE matching) | `angr_expanded` | pyelftools version-needs |
| **Function inventory (accurate recovery)** | **`binaryninja_info`** | BN recovers more/cleaner functions on stripped code |
| **Per-function control-flow graph (blocks + edges)** | **`binaryninja_info`** | BN's CFG recovery is high fidelity and cheap in `controlFlow` mode |
| **Call graph (caller/callee)** | **`binaryninja_info`** | BN resolves callers/callees directly |
| **Data-flow points of interest (taint-reachable sinks)** | **`binaryninja_info`** | BN's MLIL SSA def-use + value-set analysis resolve call args and taint |

By default the binary is loaded in Binary Ninja's **`controlFlow`** analysis
mode, so only function and basic-block recovery runs — the heavier data-flow /
IL / decompilation passes are skipped. Enabling data-flow extraction
(`enable_data_flow`) raises the analysis mode to `full` so MLIL SSA is available.

### Data-flow / points-of-interest extraction

Binary Ninja has no single "data-flow graph" object — the DFG **is** the SSA
def-use chains in its IL. When `enable_data_flow` is on, the plugin walks MLIL
SSA backward from every dangerous call ("sink") argument, using value-set
analysis to resolve constants and def-use chains to trace provenance. An
argument is flagged `attackerControlled` when it traces back to an untrusted
**source** (`recv`, `read`, `fgets`, `getenv`, …) or a function parameter. This
reachability signal is designed to feed a downstream POI / exploit-pattern tool:
it narrows a large call list down to the sinks actually reachable from input.

What it emits (all under `pointsOfInterest`):

- **`sinkCallSites`** — calls to copy/format/exec/alloc sinks, with per-argument
  provenance (`constant`, `string`, `functionParameter`, `sourceOutput`,
  `memoryLoad`, `computed`, …), an `attackerControlled` flag, and a
  `dynamicSize` flag for copy/alloc size arguments (overflow indicator).
- **`sourceCallSites`** — untrusted-input producers.
- **`uncontrolledFormatStrings`** — variadic format calls whose format argument
  is not a constant string (format-string bug surface).
- **`indirectCalls`** — unresolved call targets (control-flow-hijack surface).
- **`attackerControlledSinkCount`** — quick prioritization counter.

## Metadata schema (`binaryNinja`)

```jsonc
{
  "coreVersion": "5.3.9757",
  "platform": "linux-aarch64",   // BN OS/ABI concept (arch/endianness/entryPoint
                                  // are owned by angrExpanded, not repeated here)
  "functionCount": 1234,          // over ALL functions
  "basicBlockCount": 9876,
  "instructionCount": 54321,
  "thunkCount": 42,
  "emittedFunctionCount": 611,    // functions actually in functions[] (post-filter)
  "controlFlowTruncated": false,  // true if functions[] was capped by max_functions
  "functions": [                  // capped at max_functions; excludes thunks,
                                  // clones, library funcs, and < min_basic_blocks
    {
      "name": "main",
      "address": "0x...",
      "basicBlockCount": 12,
      "instructionCount": 130,
      "isThunk": false,
      "basicBlocks": [            // structure only, no disassembly text
        {"start": "0x...", "end": "0x...", "instructionCount": 8,
         "edges": [{"target": "0x...", "type": "TrueBranch"},
                   {"target": "0x...", "type": "FalseBranch"}]}
      ]
    }
  ],
  "callGraph": {                  // optional (enable_call_graph)
    "main": {"calls": ["run_cmd"], "calledBy": []}
  },
  "pointsOfInterest": {           // optional (enable_data_flow)
    "sinkCallSites": [
      {
        "callSite": "0x...",
        "function": "handle_request",
        "callee": "strcpy",
        "category": "bufferCopy",
        "attackerControlled": true,
        "arguments": [
          {"index": 0, "provenance": "stackLocal", "value": null,
           "tainted": false, "taintSource": null},
          {"index": 1, "provenance": "sourceOutput", "value": null,
           "tainted": true, "taintSource": "recv"}
        ]
      },
      {
        "callSite": "0x...", "function": "parse", "callee": "memcpy",
        "category": "memoryCopy", "attackerControlled": true,
        "dynamicSize": true,        // size arg is computed, not constant
        "arguments": [ /* ... */ ]
      }
    ],
    "sourceCallSites": [
      {"callSite": "0x...", "function": "main", "callee": "recv"}
    ],
    "uncontrolledFormatStrings": [
      {"callSite": "0x...", "function": "log", "callee": "printf",
       "formatArgProvenance": "functionParameter", "attackerControlled": true}
    ],
    "indirectCalls": [
      {"callSite": "0x...", "function": "dispatch"}
    ],
    "attackerControlledSinkCount": 2,
    "pointsOfInterestTruncated": false
  }
}
```

## Settings

Read via Surfactant's `ConfigManager`, section `binary_ninja`:

| Key | Default | Effect |
|-----|---------|--------|
| `enable_control_flow_graph` | `true` | Emit the filtered per-function CFG (blocks + edges) |
| `enable_call_graph` | `false` | Emit the full caller/callee call graph (large) |
| `enable_data_flow` | `false` | Emit `pointsOfInterest` (sinks/sources/taint); forces `full` analysis mode |
| `analysis_mode` | auto | Override BN analysis mode (`controlFlow`/`basic`/`intermediate`/`full`) |
| `max_functions` | `5000` | Cap on emitted `functions[]` / analyzed-function count |
| `min_basic_blocks` | `2` | Minimum blocks for a function to appear in `functions[]`; set to `1` to emit every function (incl. straight-line stubs) |
| `exclude_library_functions` | `true` | Drop C++ runtime/library functions (`std::`, `__gnu_cxx::`, `fmt::`, `spdlog::`, `cxxopts::`, `nlohmann::`) from `functions[]`; set to `false` to include them |

Aggregate statistics (`functionCount`, etc.) are always computed over **all**
functions regardless of `max_functions`, `min_basic_blocks`, and
`exclude_library_functions`. To cut bloat, the emitted `functions[]` CFG excludes
thunks, functions with no real control flow (fewer than `min_basic_blocks` basic
blocks), compiler-generated clones (`.cold`/`.isra`/`.constprop`/`.part`), and —
unless disabled — C++ runtime/library functions matched by mangled or demangled
name prefix. Those stubs and library internals otherwise dominate the output.
The call graph and data-flow POIs are opt-in.
`enable_data_flow` is the heavier feature: it raises the analysis mode to `full`
(unless `analysis_mode` overrides it) so Binary Ninja produces MLIL SSA and
value-set results.

## How it works

1. `identify` / `supports_file` limits analysis to `ELF`, `PE`, `MACHO`,
   `MACHOFAT`. For ELF, an additional `e_type` check restricts analysis to
   **true loadable executables** — `ET_EXEC` and `ET_DYN` (shared objects / PIE)
   — and **excludes** `ET_REL` relocatable objects, which is what Linux kernel
   modules (`.ko`) and `.o` files are, as well as core dumps.
2. Binary Ninja is imported **lazily**. If the API is not importable (not on
   `sys.path`, unlicensed, etc.) the plugin logs a warning and skips — SBOM
   generation is never blocked.
3. `binaryninja.load(path, options={"analysis.mode": <mode>})` produces the
   `BinaryView`. With data-flow off the mode is `controlFlow` (CFG only); with
   it on the mode is `full` so MLIL SSA is available. The plugin walks
   `view.functions` once for stats + the per-function CFG, then optionally the
   call graph and the data-flow points of interest.
4. For POIs, each dangerous call's arguments are classified by a bounded
   backward walk over MLIL SSA def-use chains (depth-capped). Value-set analysis
   resolves constants/strings; reaching a source call output or a function
   parameter marks the argument `attackerControlled`.


## Environment

The Binary Ninja Python API and a valid license must be available to the Python
interpreter running Surfactant. Typical options:

- Run Binary Ninja's `scripts/install_api.py` once to drop a `.pth` into the
  active environment, **or**
- Add the API directory to `PYTHONPATH` (e.g.
  `.../binaryninja/python`).

No environment setup is performed by this plugin.
