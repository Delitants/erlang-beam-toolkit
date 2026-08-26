# Erlang BEAM Toolkit

A vendor-neutral Linux toolkit for authorized Erlang BEAM inspection,
round-trip-safe structural patching, complete static flow analysis, dynamic-call
resolution, and selectable isolated or live runtime tracing. It produces
consultable TERM inventories plus JSON, DOT, GraphML, SVG, and self-contained
HTML flow views.

Use it only on modules and runtimes you are authorized to inspect or trace.
Live tracing can add substantial latency and data volume; bounded capture is
the default.

## Requirements

- Linux with Bash 4 or later and GNU core utilities;
- Erlang/OTP 27, 28, or 29, including `erl`, `erlc`, and `escript` from one
  installation;
- `gzip` for outer-gzip inputs;
- Graphviz `dot` is optional and enables SVG output.

The delivered script is standalone and has no Docker runtime dependency.
Docker may be used as a test boundary. Choose a matching OTP installation with
`--runtime-bin /path/to/otp/bin`; selected executable paths and OTP/ERTS
versions are recorded in provenance.

## Install

```bash
install -m 755 beam_patch_toolkit.sh "$HOME/.local/bin/beam_patch_toolkit.sh"
beam_patch_toolkit.sh help
```

The embedded help is the complete command reference, including selectors,
defaults, safety acknowledgements, output authority, and exit statuses.

## Static flow analysis

Analyze one file:

```bash
beam_patch_toolkit.sh flow --mode static --scope single \
  --beam /path/to/module.beam --output /safe/new/module-flow \
  --runtime-bin /path/to/otp/bin
```

Analyze explicit files and immediate `.beam` children of explicit directories:

```bash
beam_patch_toolkit.sh flow --mode static --scope supplied \
  --beam /path/to/first.beam --beam-dir /path/to/ebin \
  --output /safe/new/application-flow --runtime-bin /path/to/otp/bin
```

Use `--scope tree` to recurse through explicit directory roots. Static output
has no record filters: it includes every discovered module, decoded function,
entry label, instruction, source-line location available in the BEAM, CFG edge,
dependency, external call, dynamic call, unresolved record, and unsupported
record. Dynamic `apply`, fun calls, and BEAM apply forms are classified as
exact, possible, partial, or unresolved with retained evidence.

Open `flow.html` locally for an interactive Ghidra-like navigation view, or
query a committed graph without re-analysis:

```bash
beam_patch_toolkit.sh flow-query --graph /safe/new/application-flow \
  --from sample_module:start/0 --direction both --max-depth 6 --format term \
  --runtime-bin /path/to/otp/bin
```

See [static flow semantics](docs/flow-analysis.md) and
[output authority](docs/output-formats.md).

## Isolated-runtime tracing

First build the complete static graph. Then validate and run a declarative
scenario against only the explicitly supplied modules:

```bash
beam_patch_toolkit.sh trace-scenario-check \
  --scenario examples/flow_scenario.term --runtime-bin /path/to/otp/bin

beam_patch_toolkit.sh flow --mode isolated-runtime \
  --graph /safe/new/application-flow \
  --scenario examples/flow_scenario.term \
  --isolation process --output /safe/new/isolated-trace \
  --runtime-bin /path/to/otp/bin
```

This starts a disposable peer node, verifies the byte identity of every module,
loads the selected modules, runs only declared steps, captures exact trace ETF,
and shuts the peer down. Loading invokes any declared `on_load`; it is reported
and never filtered. Process isolation is not a security sandbox.

## Bounded and unbounded live tracing

Live mode observes an already running distributed Erlang node without replacing
its code or restarting its application. The cookie must be a non-symlink,
owner-only file.

```bash
beam_patch_toolkit.sh flow --mode live-runtime \
  --graph /safe/new/application-flow --node application@host.example \
  --cookie-file /safe/secret/cookie \
  --process registered:application_server \
  --functions all-supplied --events all \
  --trace-backend auto --duration 30 --max-events 100000 \
  --max-bytes 1073741824 --output /safe/new/live-trace \
  --runtime-bin /path/to/otp/bin
```

`auto` selects an isolated trace session, then an isolated `dbg` session; it
never selects the legacy global API. Explicit legacy mode requires two risk
flags. Quota-free capture requires
`--unbounded-live-trace --acknowledge-live-risk`; SIGINT/SIGTERM still performs
owned cleanup and commits partial evidence. Read
[runtime tracing](docs/runtime-tracing.md) before using live mode.

## Structural patching

The safe sequence is: `doctor`, `extract`, unchanged `roundtrip`, `verify`,
export or exact-term rewrite, `validate-assembly`, `rebuild`, and `verify`
again. Full-function exports are bound to the source assembly SHA-256, module,
MFA, entry label, and exact owned-label set. No command balances braces or
replaces an arbitrary textual suffix.

```bash
beam_patch_toolkit.sh doctor --input /path/to/module.beam \
  --runtime-bin /path/to/otp/bin
beam_patch_toolkit.sh extract --input /path/to/module.beam \
  --workspace /safe/new/module-workspace --runtime-bin /path/to/otp/bin
beam_patch_toolkit.sh roundtrip --input /path/to/module.beam \
  --workspace /safe/new/module-workspace --runtime-bin /path/to/otp/bin
```

Continue with the exact commands and evidence levels in
[structural patching](docs/patching.md). Existing outputs are never overwritten;
choose a new path or use `--auto-version-output`.

## Compressed and AES-wrapped inputs

`unpack` expands one outer gzip layer and validates the resulting FOR1/BEAM
container. `decrypt-aes` supports the documented Dbgi/Abst AES-256-CTR envelope
and reconstructs Code/LitT only after structural checks. Both 256-bit keys must
be in distinct owner-only files containing exactly 64 hexadecimal characters:

```bash
beam_patch_toolkit.sh decrypt-aes --input /path/to/wrapped.input \
  --output /safe/new/decrypted.beam \
  --key1-file /safe/secret/key1 --key2-file /safe/secret/key2 \
  --runtime-bin /path/to/otp/bin
```

Keys are never accepted as command-line values, printed, or copied into a
workspace.

## Output files

`flow-ir.term` is authoritative static data. `events.raw.etf` is authoritative
runtime data. Family TERM files are convenient complete inventories; JSON,
JSONL, DOT, SVG, GraphML, and HTML are reconciled derived views. A successful
directory transaction writes `.beam-flow-ir` or `.beam-flow-trace` last.
Incomplete directories are not valid artifacts.

Runtime output adds process identity/parentage, observed call/return/exception
counts, spawn and matched/unmatched message edges, unmatched static/runtime
targets, a chronological JSON timeline, and an additive runtime graph. It does
not rewrite or filter the static IR.

## OTP compatibility and limits

The release is tested on OTP 27, 28, and 29. BEAM opcode and assembly formats
are OTP-sensitive, so use the closest matching runtime and require an unchanged
round trip before editing. Static analysis cannot prove values unavailable in
the bytecode; such calls remain explicit partial or unresolved records. Runtime
observation proves only exercised paths and does not disprove other static
possibilities.

The offline HTML is a navigation and evidence viewer, not an Erlang source
decompiler. Namespace isolation is a reserved explicit capability request in
this release; process isolation is implemented and is not a hostile-code
sandbox.

## Safety and privacy

- Input modules are never loaded by static, extraction, rebuild, or verify
  commands. Isolated scenarios deliberately load them and may run `on_load`.
- Live mode preflights loaded paths, adds a temporary tracing agent, verifies
  code identity afterward, unloads the agent, and proves owned trace cleanup.
- A cleanup failure produces partial evidence and exit 70; inspect the manifest
  before any retry.
- Cookie and AES key files must be owner-only. Release publication excludes
  BEAMs, secrets, trace captures, crash dumps, target paths, and private handoff
  notes.
- Structural/load checks are not application-behavior proof. Test a candidate
  in a disposable matching runtime before any separately authorized deployment.

## Development verification

The regression harness creates only disposable generic fixtures outside the
repository and exercises static IR reconciliation, isolated scenarios, bounded
and interrupted live tracing, every backend, structural patching, gzip/AES
handling, and output exclusivity. GitHub Actions runs it independently in the
official Erlang OTP 27, 28, and 29 Linux containers:

```bash
bash tests/test_publication_scan.sh
bash tests/publication_scan.sh
bash -n beam_patch_toolkit.sh
bash tests/test_beam_patch_toolkit.sh
```

The publication scan permits only the documented source allowlist and rejects
generated BEAMs, keys, cookies, trace ETF, crash dumps, candidate/decrypted
artifacts, symlinks, private handoffs, local paths, target addresses, private
key markers, and product-specific identifiers.

## License

[MIT](LICENSE)
