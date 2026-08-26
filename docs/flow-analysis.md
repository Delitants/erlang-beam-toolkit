# Static flow analysis

`flow --mode static` disassembles every discovered module without loading it.
The discovery boundary is explicit: `single` accepts one `--beam`, `supplied`
combines explicit files with immediate `.beam` children of explicit
directories, and `tree` recursively visits only explicit directory roots.

Every decoded function, instruction, label, basic block, edge, callsite,
unknown, and unsupported record is retained. Stable IDs derive from module,
function, arity, entry label, block label/ordinal, and instruction ordinal;
pretty-printer line numbers are never identities.

Function records include module, name, arity, entry label, BEAM path, and every
available source-file/line annotation. Dependencies retain the exact caller,
target or partial target, instruction, block/label position, source annotation,
and certainty. There are no authoritative-output filters.

Basic blocks split at labels and after control transfers. Edges distinguish
fallthrough, jump, test pass/fail, selection case/default, receive wait,
message match, timeout, protected-body, and exception paths. A `func_info`
error target is terminal rather than fallthrough.

The abstract interpreter propagates X/Y-register values to a fixed point over
the CFG. It records incoming and outgoing state for every block, including an
explicit unreachable state. Joins preserve bounded unions and record widening.
Dynamic calls are classified per callsite as `exact`, `possible`, `partial`, or
`unresolved`; known components and reasons are retained. This covers direct and
tail calls, `apply`/`apply_last`, `erlang:apply/2,3`, fun construction and
invocation, and `call_fun` variants. Unsupported opcode shapes remain explicit
records rather than disappearing.

Calls are linked across the complete supplied module universe. Missing targets
remain named external nodes, while incomplete dynamic calls remain unresolved
nodes. Strongly connected components identify direct and mutual recursion.

`flow.html` embeds the complete normalized IR and has no network dependencies.
Its inventory, call-flow, CFG, dependency, dynamic-call, and unknown views are
navigational views over that full dataset. Search changes only what is shown;
it never removes records from the embedded authoritative inventory.

`flow-query` reads a committed `.beam-flow-ir` directory and performs bounded
caller/callee traversal without re-analysis. Each result carries both complete
graph counts and focused-view counts.

Runtime modes create a separate overlay and never rewrite `flow-ir.term`.
Observed calls, returns, exceptions, processes, spawns, and messages link to
stable static IDs where evidence is sufficient. Unmatched observations remain
first-class records. See [runtime tracing](runtime-tracing.md) for selectable
backends, instrumentation boundaries, and cleanup semantics.
