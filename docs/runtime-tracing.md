# Runtime tracing

Runtime tracing adds observed execution evidence to a committed complete static
graph. It never deletes a static function, call possibility, dependency, or
unknown. Observed and unobserved are runtime states, not proof that code is
reachable or unreachable for every input.

## Modes

| Mode | Target | Code loading | Main use |
| --- | --- | --- | --- |
| `static` | BEAM files | none | complete decoded inventory and graph |
| `isolated-runtime` | disposable peer node | supplied modules | controlled scenarios and `on_load` behavior |
| `live-runtime` | existing distributed node | temporary toolkit agent only | bounded observation of real behavior |

All three are selected with `flow --mode`. Static output is required before a
runtime mode so observations can be correlated to stable function and callsite
IDs.

## Isolated scenarios

A `beam_flow_scenario_v1` file is exactly one Erlang map term. It declares a
positive timeout and an ordered list of strict steps. Supported operations load
an explicitly supplied module, call an MFA, spawn a worker, send or receive an
exact term, assert an exact value, stop a process, and sleep for a bounded
period. Bindings make process/message relationships explicit. Unknown keys,
undefined bindings, steps after stop, and modules outside the graph fail
validation.

See [`examples/flow_scenario.term`](../examples/flow_scenario.term) for a
ready-to-run harmless fixture scenario. Validate before capture:

```bash
beam_patch_toolkit.sh trace-scenario-check \
  --scenario /path/to/scenario.term --runtime-bin /path/to/otp/bin
```

`--isolation process` starts an OTP `peer` node with no inherited code path,
verifies each supplied BEAM digest, loads only declared modules, and tears the
peer down. `auto` currently chooses the same process isolation. This separates
state but is not a hostile-code security sandbox. `namespace` is reserved for
an explicit capability implementation and fails closed when unavailable.

A module's `on_load` callback is part of its behavior. Static analysis reports
the attribute and decoded function without invoking it. An isolated scenario
that loads the module does invoke it; the result is captured. Nothing is
filtered merely because it is `on_load`.

## Live preflight

Live mode requires a distributed node name, a complete graph, and an
owner-only cookie file. Preflight confirms:

- controller connectivity and target node identity;
- OTP/ERTS versions and supported tracing APIs;
- every graph module is already loaded and its path is recorded;
- the temporary toolkit agent is not already loaded.

The toolkit then loads only its temporary tracing agent, captures within the
selected boundary, drains trace delivery, destroys its owned tracing state,
unloads the agent, compares module paths before and after, and confirms the node
still responds. It never replaces target application code or restarts the
application.

## Backends

| Backend | Selection | State behavior |
| --- | --- | --- |
| `auto` | default | chooses `session`, then `dbg`; never legacy |
| `session` | explicit | OTP `trace` session owned and destroyed by this run |
| `dbg` | explicit | isolated `dbg` session; its underlying owned trace session is also checked and destroyed |
| `legacy` | explicit plus both risk flags | snapshots selected global state, applies exact patterns, restores and verifies it |

Legacy mode requires `--trace-backend legacy --allow-legacy-live-trace
--acknowledge-live-risk`. It does not clear global tracing indiscriminately.
Concurrent modification of selected legacy state is reported as a cleanup
conflict and makes the run partial.

## Selectors

Selectors control what is instrumented. They do not post-filter captured
events, and they never alter the authoritative static graph.

Repeatable `--process` values:

| Selector | Meaning |
| --- | --- |
| `all` | existing non-tool processes plus processes created afterward |
| `existing` | existing non-tool processes only |
| `new` | processes created afterward |
| `registered:NAME` | one existing registered process |
| `pid:<PID>` | one exact existing local PID on the target node |

At least one process selector is mandatory. `all` can be expensive.

Repeatable `--functions` values:

| Selector | Meaning |
| --- | --- |
| omitted or `all-supplied` | every function in the complete supplied graph |
| `all-loaded` | every loaded function; highest overhead |
| `MODULE:FUNCTION/ARITY` | one exact graph MFA |
| `MODULE:_/ARITY` | every matching function at one arity |
| `MODULE:FUNCTION/_` | every arity of one function |

Wildcard module names are deliberately unsupported: the module must be present
in the graph so scope remains auditable.

Repeatable `--events` values are `all`, `call`, `return`, `exception`,
`process`, `send`, `receive`, `garbage_collection`, and `scheduler`. Omitting
the option enables call, process, send, and receive families. A monotonic
timestamp is always attached. Return and exception evidence uses local function
patterns and therefore shares call instrumentation.

## Bounds, interruption, and overhead

The default stop limits are 30 seconds, 100000 events, and 1073741824 captured
bytes. Set smaller positive `--duration`, `--max-events`, and `--max-bytes`
values for production-sensitive nodes. The first reached limit is recorded in
the capture manifest.

Quota-free tracing is available only with the exact pair
`--unbounded-live-trace --acknowledge-live-risk`. It can consume unbounded
memory, disk, scheduler time, and network bandwidth. Run it in the foreground;
SIGINT or SIGTERM writes an authenticated local control request, asks the
specific remote run to stop, drains events, cleans up, and commits the evidence
already captured.

Overhead grows with selected processes, matched functions, event families,
call rate, message rate, and term size. `all-loaded`, `--process all`, scheduler
events, and garbage-collection events are broad choices. Start with an exact
registered process and graph functions where possible.

## Cleanup and recovery

`trace-manifest.term` records arming results, the selected backend, stop reason,
delivery barrier, session destruction, agent unload, post-run responsiveness,
and code-path identity. `trace-completeness.term` reconciles raw frames and
normalized records. `.beam-flow-trace` is written last.

If drain, cleanup, agent unload, target response, or code identity cannot be
confirmed, the directory is committed as `partial` and the command exits 70.
Preserve it. Do not blindly run a global trace-clear command: that can destroy
another operator's tracing state. Inspect the exact owned targets and
`manual_cleanup` records in the manifest, coordinate with the node owner, and
apply only those operations. For a disposable isolated node, terminate that
specific peer. For an existing live node, confirm its current trace owner first
because concurrent state may have changed since the snapshot.

## Runtime artifacts

`events.raw.etf` is authoritative: each event is an exact ETF term with an
unsigned 64-bit big-endian length prefix. `events.term`, normalized JSONL, and
`timeline.json` preserve sequence and correlation fields.

`runtime-overlay.term` correlates events to the unchanged static graph.
`runtime-processes.term` records stable runtime IDs, parentage, lifespan, and
exit evidence. `runtime-edges.term` contains observed call, spawn, and matched
or unmatched message edges. `runtime-unmatched.term` retains observed MFAs that
cannot be mapped, with reasons such as an unsupplied module. `runtime.dot`,
optional `runtime.svg`, and offline `flow.html` are derived views.

Runtime observation never reduces static certainty. A call seen once is
observed; a static alternative not seen during the scenario remains possible.
