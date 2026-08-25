# surfactantplugin-binaryninja-info

A Surfactant plugin that uses **Binary Ninja** for high-fidelity *structural*
code analysis and embeds the results into the generated SBOM under the
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
| **Call graph (caller/callee)** | **`binaryninja_info`** | BN resolves callers/callees directly |
| **Notable-API cross-references** | **`binaryninja_info`** | BN xrefs show *which* functions call a sink |
| **Typed function prototypes (decompiler)** | **`binaryninja_info`** | BN's IL/decompiler recovers variables & types |

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
  "inventoryTruncated": false,    // true if functions[] was capped
  "notableApiReferences": {       // api -> functions that call it (xrefs)
    "system": ["main", "run_cmd"],
    "strcpy": ["parse_args"]
  },
  "functions": [                  // capped at max_functions (default on)
    {"name": "main", "address": "0x...", "basicBlockCount": 12,
     "instructionCount": 130, "parameterCount": 2, "isThunk": false}
  ],
  "callGraph": {                  // optional (enable_call_graph)
    "main": {"calls": ["run_cmd"], "calledBy": []}
  },
  "functionPrototypes": [         // optional (enable_decompilation)
    {"name": "main", "prototype": "int32_t main(int32_t argc, char** argv)"}
  ]
}
```

## Settings

Read via Surfactant's `ConfigManager`, section `binary_ninja`:

| Key | Default | Effect |
|-----|---------|--------|
| `enable_function_list` | `true` | Emit the capped per-function inventory |
| `enable_call_graph` | `false` | Emit the full caller/callee call graph (large) |
| `enable_decompilation` | `false` | Emit typed function prototypes (large) |
| `max_functions` | `5000` | Cap on `functions[]` / `functionPrototypes[]` size |

Aggregate statistics (`functionCount`, etc.) are always computed over **all**
functions regardless of `max_functions`. The heavier signals (call graph,
prototypes) are opt-in to keep SBOMs manageable.

## How it works

1. `identify` / `supports_file` limits analysis to `ELF`, `PE`, `MACHO`,
   `MACHOFAT`. For ELF, an additional `e_type` check restricts analysis to
   **true loadable executables** — `ET_EXEC` and `ET_DYN` (shared objects / PIE)
   — and **excludes** `ET_REL` relocatable objects, which is what Linux kernel
   modules (`.ko`) and `.o` files are, as well as core dumps.
2. Binary Ninja is imported **lazily**. If the API is not importable (not on
   `sys.path`, unlicensed, etc.) the plugin logs a warning and skips — SBOM
   generation is never blocked.
3. `binaryninja.load(path)` produces a fully-analyzed `BinaryView`; the plugin
   walks `view.functions` once to compute stats + inventory, then optionally the
   call graph, notable-API xrefs, and typed prototypes.

## Environment

The Binary Ninja Python API and a valid license must be available to the Python
interpreter running Surfactant. Typical options:

- Run Binary Ninja's `scripts/install_api.py` once to drop a `.pth` into the
  active environment, **or**
- Add the API directory to `PYTHONPATH` (e.g.
  `.../binaryninja/python`).

No environment setup is performed by this plugin.
