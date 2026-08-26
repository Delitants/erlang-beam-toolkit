# Output formats

Every successful `flow --mode static` command commits one graph directory. The
`.beam-flow-ir` marker is written last; a directory without that marker is not a
complete graph.

`flow-ir.term` is the authoritative static artifact. It is one consultable
`beam_flow_ir_v1` map containing every module, function, block, instruction,
CFG edge, block state, callsite, call edge, unresolved record, unsupported
record, recursive component, and reconciled record count. The family-specific
`.term` files expose the same records for convenient streaming and inspection.

`flow-ir.json` is a complete normalized representation of the TERM data.
Atoms become strings. Values that have no lossless native JSON representation
carry both a printable Erlang term and base64 ETF. Arbitrary non-UTF-8 binaries
use a base64 wrapper. Counts in TERM and JSON must match.

`callgraph.dot`, `callgraph.graphml`, and the files under `cfg/` are derived
views. Function filenames use a bounded hexadecimal digest and are mapped back
to stable function IDs by `cfg-index.term`. If Graphviz `dot` is installed,
`callgraph.svg` and one SVG beside every CFG DOT file are generated before the
transaction commits.

TERM is authoritative for static analysis. Raw length-framed ETF is
authoritative for runtime capture. JSON, JSONL, DOT, SVG, GraphML, and HTML are
derived representations and must reconcile with their authoritative counts.
Focused `flow-query` results always include both authoritative graph counts and
view counts, so a view cannot be mistaken for filtered source data.

A successful runtime transaction writes `events.raw.etf`, `events.term`,
`events.normalized.jsonl`, `timeline.json`, `runtime-overlay.term`,
`runtime-processes.term`, `runtime-edges.term`, `runtime-unmatched.term`,
`runtime.dot`, optional `runtime.svg`, offline `flow.html`,
`trace-manifest.term`, and `trace-completeness.term`. The
`.beam-flow-trace` marker is committed last.

Each raw event is prefixed by an unsigned 64-bit big-endian payload length. The
payload is the exact ETF trace term received from the backend. Normalized events
add stable sequence, portable PID/port/reference values, call depth, and
correlation state. `trace-raw-check` validates every frame independently.

Runtime overlays are additive. They preserve the authoritative static counts
and a deterministic digest of the static call edges, record observed and
unobserved functions, correlate call outcomes and exceptions, build process
parentage, and retain matched/unmatched message and MFA evidence. The runtime
DOT/SVG/HTML files are visualizations of those records, not replacements for
TERM/ETF evidence.
