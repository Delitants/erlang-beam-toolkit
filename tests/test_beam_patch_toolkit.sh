#!/usr/bin/env bash
# Regression harness for the public beam_patch_toolkit.sh contract.
# Breaks caught: unsafe paths accepted, a BEAM is modified/overwritten, or an
# edited, benign symbolic assembly cannot be rebuilt and used in isolation.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TOOL=${TOOL:-"$ROOT/beam_patch_toolkit.sh"}
FIXTURE_SOURCE="$ROOT/tests/fixtures/base_fixture.erl"
AES_FIXTURE_BUILDER="$ROOT/tests/make_aes_fixture.escript"
FLOW_BRANCH_SOURCE="$ROOT/tests/fixtures/flow_branch_fixture.erl"
FLOW_CROSS_A_SOURCE="$ROOT/tests/fixtures/flow_cross_a.erl"
FLOW_CROSS_B_SOURCE="$ROOT/tests/fixtures/flow_cross_b.erl"
FLOW_RUNTIME_SOURCE="$ROOT/tests/fixtures/flow_runtime_fixture.erl"
FLOW_ON_LOAD_SOURCE="$ROOT/tests/fixtures/flow_on_load_fixture.erl"
FLOW_SCENARIO_SOURCE="$ROOT/examples/flow_scenario.term"
PATCH_VARIANT_BUILDER="$ROOT/tests/make_patch_variants.escript"
PUBLICATION_SCAN_TEST="$ROOT/tests/test_publication_scan.sh"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/beam-patch-toolkit-test.XXXXXX")
LIVE_TARGET_PID=
cleanup_tests() {
  if [[ -n ${LIVE_TARGET_PID:-} ]] && kill -0 "$LIVE_TARGET_PID" 2>/dev/null; then
    kill -TERM "$LIVE_TARGET_PID" 2>/dev/null || true
    wait "$LIVE_TARGET_PID" 2>/dev/null || true
  fi
  if [[ ${KEEP_TEST_TMP:-0} == 1 ]]; then
    printf 'test artifacts kept: %s\n' "$TMP_ROOT" >&2
  else
    rm -rf -- "$TMP_ROOT"
  fi
}
trap cleanup_tests EXIT

failures=0

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }

assert_status() {
  local expected=$1 description=$2
  shift 2
  local output status
  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  if [[ $status -eq $expected ]]; then
    pass "$description"
  else
    printf '%s\n' "$output" >&2
    fail "$description (expected status $expected, got $status)"
  fi
}

assert_success() { assert_status 0 "$@"; }

assert_contains() {
  local needle=$1 haystack=$2 description=$3
  if [[ $haystack == *"$needle"* ]]; then
    pass "$description"
  else
    printf 'missing [%s] in:\n%s\n' "$needle" "$haystack" >&2
    fail "$description"
  fi
}

assert_file() {
  local path=$1 description=$2
  if [[ -f $path ]]; then pass "$description"; else fail "$description ($path missing)"; fi
}

assert_absent() {
  local path=$1 description=$2
  if [[ ! -e $path && ! -L $path ]]; then pass "$description"; else fail "$description ($path exists)"; fi
}

if [[ ! -x $TOOL ]]; then
  printf 'tool is not executable: %s\n' "$TOOL" >&2
  exit 1
fi

help_output=$("$TOOL" help)
assert_contains 'roundtrip --input BEAM --workspace DIR' "$help_output" 'help documents roundtrip arguments'
assert_contains 'unpack --input INPUT --output OUTPUT' "$help_output" 'help documents outer-gzip unpacking'
assert_contains 'decrypt-aes --input INPUT --output OUTPUT --key1-file FILE --key2-file FILE' "$help_output" 'help documents AES key-file decryption'
assert_contains 'export-function --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --output FUNCTION.term' "$help_output" 'help documents function-level export'
assert_contains 'replace-function --workspace WORKSPACE --assembly ASSEMBLY.S --function FUNCTION.term --output EDITED.S' "$help_output" 'help documents structural function replacement'
assert_contains 'rewrite-function-term --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --from-term FROM.term --to-term TO.term --expected-count N --output EDITED.S' "$help_output" 'help documents parsed exact-term function rewriting'
assert_contains 'validate-assembly --workspace WORKSPACE --assembly ASSEMBLY.S' "$help_output" 'help documents parse and assembly validation'
assert_contains 'workspace-status --workspace DIR' "$help_output" 'help documents workspace diagnosis'
assert_contains '--auto-version-output' "$help_output" 'help documents safe automatic output versioning'
assert_contains '--runtime-bin DIR' "$help_output" 'help documents explicit matching-runtime selection'
assert_contains 'OTP 27, 28, and 29' "$help_output" 'help documents supported OTP majors'
assert_contains 'neutral-line-canary --workspace WORKSPACE --entry-label N --output EDITED.S' "$help_output" 'help documents provenance-bound neutral line canary arguments'
assert_contains 'rebuild --workspace WORKSPACE --assembly EDITED.S --output CANDIDATE.beam' "$help_output" 'help documents provenance-bound rebuild arguments'
assert_contains 'no filters' "$help_output" 'help documents complete unfiltered inventories'
assert_contains 'flow --mode MODE' "$help_output" 'help documents flow modes'
assert_contains 'flow-query --graph FLOW_DIR' "$help_output" 'help documents graph queries'
assert_contains 'trace-scenario-check --scenario SCENARIO.term' "$help_output" 'help documents scenario validation'
assert_contains 'trace-raw-check --input events.raw.etf' "$help_output" 'help documents framed ETF validation'
assert_contains 'single, supplied, tree' "$help_output" 'help documents all static scopes'
assert_contains '--unbounded-live-trace --acknowledge-live-risk' "$help_output" 'help documents unbounded acknowledgement'
assert_contains 'Backends: auto, session, dbg, legacy.' "$help_output" 'help documents every selectable trace backend'
assert_contains 'Isolation choices: auto, process, namespace.' "$help_output" 'help documents every selectable isolation choice'
assert_contains 'Process selectors: all, existing, new, registered:NAME, pid:<PID>.' "$help_output" 'help documents every process selector'
assert_contains 'Function selectors: all-supplied, all-loaded, MODULE:FUNCTION/ARITY' "$help_output" 'help documents complete function selector syntax'
assert_contains 'Event selectors: all, call, return, exception, process, send, receive,' "$help_output" 'help documents every event selector'
assert_contains 'auto selects session, then dbg; it never selects legacy' "$help_output" 'help documents safe automatic backend selection'
assert_contains 'Default live bounds: duration=30 seconds, max-events=100000,' "$help_output" 'help documents bounded live defaults'
assert_contains 'A cleanup failure commits partial evidence and exits 70.' "$help_output" 'help documents partial cleanup evidence'
assert_contains 'Authoritative: flow-ir.term for static analysis and events.raw.etf' "$help_output" 'help identifies authoritative artifacts'
assert_contains 'Directions: callers, callees, both. Formats: term, json.' "$help_output" 'help documents query views and formats'
assert_contains 'The function wrapper is bound to source SHA-256, module, MFA, entry,' "$help_output" 'help documents structural patch identity binding'
assert_contains '70 processing, validation, or partial-trace failure' "$help_output" 'help documents processing failure status'
assert_success 'publication scanner rejects private and generated artifacts' \
  bash "$PUBLICATION_SCAN_TEST"
assert_status 64 'flow requires mode and output' "$TOOL" flow
assert_status 64 'unbounded mode requires acknowledgement' "$TOOL" flow --mode live-runtime --unbounded-live-trace --output "$TMP_ROOT/trace"
assert_status 64 'live-risk acknowledgement alone does not enable a mode' "$TOOL" flow --mode live-runtime --acknowledge-live-risk --output "$TMP_ROOT/trace-ack-only"
assert_status 64 'legacy live tracing requires its explicit permission flag' "$TOOL" flow --mode live-runtime --trace-backend legacy --acknowledge-live-risk --output "$TMP_ROOT/trace-legacy-no-permission"
assert_status 64 'legacy permission without risk acknowledgement is insufficient' "$TOOL" flow --mode live-runtime --trace-backend legacy --allow-legacy-live-trace --output "$TMP_ROOT/trace-legacy-no-ack"
assert_status 64 'flow-query requires graph and origin' "$TOOL" flow-query
assert_status 64 'scenario checker requires a scenario' "$TOOL" trace-scenario-check
assert_status 64 'raw trace checker requires an input' "$TOOL" trace-raw-check
assert_status 64 'extract requires input and workspace' "$TOOL" extract
assert_status 64 'unpack requires input and output' "$TOOL" unpack
assert_status 64 'decrypt-aes requires input output and both key files' "$TOOL" decrypt-aes
assert_status 64 'export-function requires all options' "$TOOL" export-function
assert_status 64 'replace-function requires all options' "$TOOL" replace-function
assert_status 64 'rewrite-function-term requires all options' "$TOOL" rewrite-function-term
assert_status 64 'validate-assembly requires all options' "$TOOL" validate-assembly
assert_status 66 'doctor rejects missing input' "$TOOL" doctor --input "$TMP_ROOT/missing.beam"
assert_status 64 'missing option value is usage failure' "$TOOL" doctor --input
assert_status 64 'runtime-bin missing value is usage failure' "$TOOL" doctor --runtime-bin
printf 'not a beam\n' >"$TMP_ROOT/not-a-beam"
assert_status 66 'workspace-status reports a missing workspace' "$TOOL" workspace-status --workspace "$TMP_ROOT/missing-workspace"
assert_status 66 'runtime-bin rejects a missing runtime directory' "$TOOL" doctor --input "$TMP_ROOT/not-a-beam" --runtime-bin "$TMP_ROOT/no-runtime"
assert_status 64 'neutral line canary requires all options' "$TOOL" neutral-line-canary
assert_status 64 'neutral line canary rejects an invalid entry label' "$TOOL" neutral-line-canary --workspace ignored-workspace --entry-label 0 --output ignored-output.S

if ! command -v erl >/dev/null 2>&1 || ! command -v erlc >/dev/null 2>&1; then
  printf 'SKIP: Erlang compiler/runtime unavailable; CLI safety tests ran only.\n'
  (( failures == 0 ))
  exit
fi

otp_major=$(erl -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().' 2>/dev/null)
expected_erl_path=$(command -v erl)
expected_escript_path=$(command -v escript)

SCENARIO_SMOKE="$TMP_ROOT/scenario-smoke.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 1000, steps => []}.' >"$SCENARIO_SMOKE"
assert_success 'scenario checker accepts one bounded declarative scenario' \
  "$TOOL" trace-scenario-check --scenario "$SCENARIO_SMOKE" --allow-otp-major "$otp_major"

SCENARIO_UNKNOWN_OP="$TMP_ROOT/scenario-unknown-op.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 1000, steps => [#{op => evaluate, source => "halt()."}]}.' >"$SCENARIO_UNKNOWN_OP"
assert_status 70 'scenario checker rejects unknown operations and source evaluation' \
  "$TOOL" trace-scenario-check --scenario "$SCENARIO_UNKNOWN_OP" --allow-otp-major "$otp_major"
SCENARIO_UNKNOWN_KEY="$TMP_ROOT/scenario-unknown-key.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 1000, steps => [#{op => stop, surprise => true}]}.' >"$SCENARIO_UNKNOWN_KEY"
assert_status 70 'scenario checker rejects unknown operation keys' \
  "$TOOL" trace-scenario-check --scenario "$SCENARIO_UNKNOWN_KEY" --allow-otp-major "$otp_major"
SCENARIO_UNDEFINED_BINDING="$TMP_ROOT/scenario-undefined-binding.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 1000, steps => [#{op => send, target => {binding, absent}, message => sample}, #{op => stop}]}.' >"$SCENARIO_UNDEFINED_BINDING"
assert_status 70 'scenario checker rejects forward or undefined binding references' \
  "$TOOL" trace-scenario-check --scenario "$SCENARIO_UNDEFINED_BINDING" --allow-otp-major "$otp_major"
SCENARIO_BAD_ARITY="$TMP_ROOT/scenario-bad-arity.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 1000, steps => [#{op => call, mfa => {erlang, length, 1}, args => []}, #{op => stop}]}.' >"$SCENARIO_BAD_ARITY"
assert_status 70 'scenario checker rejects MFA and argument arity mismatches' \
  "$TOOL" trace-scenario-check --scenario "$SCENARIO_BAD_ARITY" --allow-otp-major "$otp_major"

FAILED_EXTRACT_WORKSPACE="$TMP_ROOT/failed transactional extraction"
set +e
failed_extract_output=$("$TOOL" extract --input "$TMP_ROOT/not-a-beam" --workspace "$FAILED_EXTRACT_WORKSPACE" --allow-otp-major "$otp_major" 2>&1)
failed_extract_status=$?
set -e
if [[ $failed_extract_status -eq 70 && ! -e $FAILED_EXTRACT_WORKSPACE ]]; then
  pass 'failed extraction leaves no partial target workspace'
else
  printf '%s\n' "$failed_extract_output" >&2
  fail "failed extraction leaves no partial target workspace (status $failed_extract_status)"
fi

INCOMPLETE_WORKSPACE="$TMP_ROOT/incomplete marked workspace"
mkdir "$INCOMPLETE_WORKSPACE"
: >"$INCOMPLETE_WORKSPACE/.beam-patch-workspace"
: >"$INCOMPLETE_WORKSPACE/original.beam"
set +e
incomplete_status_output=$("$TOOL" workspace-status --workspace "$INCOMPLETE_WORKSPACE" 2>&1)
incomplete_status=$?
set -e
if [[ $incomplete_status -eq 0 && $incomplete_status_output == *'state=incomplete'* && $incomplete_status_output == *'missing='* ]]; then
  pass 'workspace-status identifies and explains an incomplete marked workspace'
else
  printf '%s\n' "$incomplete_status_output" >&2
  fail "workspace-status identifies and explains an incomplete marked workspace (status $incomplete_status)"
fi
set +e
incomplete_extract_output=$("$TOOL" extract --input "$TMP_ROOT/not-a-beam" --workspace "$INCOMPLETE_WORKSPACE" --allow-otp-major "$otp_major" 2>&1)
incomplete_extract_status=$?
set -e
if [[ $incomplete_extract_status -eq 73 && $incomplete_extract_output == *'incomplete workspace'* && $incomplete_extract_output == *'use a new --workspace path'* ]]; then
  pass 'extract rejects an old partial workspace with actionable guidance'
else
  printf '%s\n' "$incomplete_extract_output" >&2
  fail "extract rejects an old partial workspace with actionable guidance (status $incomplete_extract_status)"
fi
if [[ ${BEAM_TOOLKIT_REQUIRE_OTP27:-0} == 1 && $otp_major != 27 ]]; then
  printf 'OTP 27 required by this test run; found %s\n' "$otp_major" >&2
  exit 77
fi

if [[ -n ${BEAM_TOOLKIT_NEWER_BEAM:-} ]]; then
  if [[ $otp_major -lt 28 ]]; then
    set +e
    newer_doctor_output=$("$TOOL" doctor --input "$BEAM_TOOLKIT_NEWER_BEAM" --allow-otp-major "$otp_major" 2>&1)
    newer_doctor_status=$?
    set -e
    if [[ $newer_doctor_status -eq 70 && $newer_doctor_output == *runtime_too_old* && $newer_doctor_output == *minimum_otp* ]]; then
      pass 'OTP 27 rejects OTP 28+ atom encoding with an actionable preflight diagnosis'
    else
      printf '%s\n' "$newer_doctor_output" >&2
      fail 'OTP 27 rejects OTP 28+ atom encoding with an actionable preflight diagnosis'
    fi
  else
    newer_doctor_output=$("$TOOL" doctor --input "$BEAM_TOOLKIT_NEWER_BEAM" --allow-otp-major "$otp_major" 2>&1)
    assert_contains 'minimum_otp => 28' "$newer_doctor_output" 'doctor reports OTP 28 minimum from raw chunk formats'
    assert_contains 'atom_format => otp28_long_atoms' "$newer_doctor_output" 'doctor reports OTP 28 extended atom encoding'
    assert_contains 'literal_format => otp28_uncompressed' "$newer_doctor_output" 'doctor distinguishes OTP 28 uncompressed literals from zlib data'
    assert_contains 'encrypted_chunks => [<<"Dbgi">>,<<"Abst">>]' "$newer_doctor_output" 'doctor reports every AES-enveloped chunk'
    assert_contains 'packed_or_protected => true' "$newer_doctor_output" 'doctor reports header versus visible-code inconsistency'
  fi
fi

mkdir -p "$TMP_ROOT/input with spaces"
cp -- "$FIXTURE_SOURCE" "$TMP_ROOT/input with spaces/beam_patch_fixture.erl"
erlc +debug_info +no_copt -o "$TMP_ROOT/input with spaces" "$TMP_ROOT/input with spaces/beam_patch_fixture.erl"
INPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.beam"
INPUT_SHA=$(sha256sum "$INPUT" | awk '{print $1}')
FLOW_INIT="$TMP_ROOT/flow initialized"
assert_success 'static flow initializes a transactional graph directory' \
  "$TOOL" flow --mode static --scope single --beam "$INPUT" --output "$FLOW_INIT" --allow-otp-major "$otp_major"
assert_file "$FLOW_INIT/.beam-flow-ir" 'static flow commits its graph marker last'
assert_success 'static flow manifest is schema-valid and complete' \
  escript "$ROOT/tests/assert_flow.escript" manifest "$FLOW_INIT/flow-manifest.term" complete
assert_status 73 'static flow refuses an existing graph directory' \
  "$TOOL" flow --mode static --scope single --beam "$INPUT" --output "$FLOW_INIT" --allow-otp-major "$otp_major"

FLOW_BRANCH_BUILD="$TMP_ROOT/flow branch build"
mkdir -p "$FLOW_BRANCH_BUILD"
cp -- "$FLOW_BRANCH_SOURCE" "$FLOW_BRANCH_BUILD/flow_branch_fixture.erl"
erlc +debug_info +no_copt -o "$FLOW_BRANCH_BUILD" "$FLOW_BRANCH_BUILD/flow_branch_fixture.erl"
FLOW_CFG="$TMP_ROOT/flow cfg"
assert_success 'static flow analyzes every function in a branch-heavy BEAM' \
  "$TOOL" flow --mode static --scope single --beam "$FLOW_BRANCH_BUILD/flow_branch_fixture.beam" --output "$FLOW_CFG" --allow-otp-major "$otp_major"
assert_success 'static CFG artifacts are complete and referentially valid' \
  escript "$ROOT/tests/assert_flow.escript" cfg "$FLOW_CFG"
assert_success 'fixed-point dataflow resolves exact, possible, partial, and unresolved calls' \
  escript "$ROOT/tests/assert_flow.escript" dataflow "$FLOW_CFG"

FLOW_CROSS_BUILD="$TMP_ROOT/flow cross build"
mkdir -p "$FLOW_CROSS_BUILD"
cp -- "$FLOW_CROSS_A_SOURCE" "$FLOW_CROSS_B_SOURCE" "$FLOW_CROSS_BUILD/"
erlc +debug_info +no_copt -o "$FLOW_CROSS_BUILD" \
  "$FLOW_CROSS_BUILD/flow_cross_a.erl" "$FLOW_CROSS_BUILD/flow_cross_b.erl"
FLOW_LINKED="$TMP_ROOT/flow linked"
assert_success 'supplied scope links every explicitly supplied BEAM' \
  "$TOOL" flow --mode static --scope supplied \
    --beam "$FLOW_CROSS_BUILD/flow_cross_a.beam" \
    --beam "$FLOW_CROSS_BUILD/flow_cross_b.beam" \
    --output "$FLOW_LINKED" --allow-otp-major "$otp_major"
assert_success 'multi-module Flow IR links calls, externals, and recursion' \
  escript "$ROOT/tests/assert_flow.escript" linked "$FLOW_LINKED"
assert_file "$FLOW_LINKED/flow-ir.json" 'static flow exports normalized JSON'
assert_file "$FLOW_LINKED/callgraph.dot" 'static flow exports DOT call graph'
assert_file "$FLOW_LINKED/callgraph.graphml" 'static flow exports GraphML call graph'
assert_success 'JSON, DOT, GraphML, and CFG indexes reconcile with TERM' \
  escript "$ROOT/tests/assert_flow.escript" formats "$FLOW_LINKED"
assert_file "$FLOW_LINKED/flow.html" 'static flow produces an offline graph explorer'
assert_success 'offline explorer embeds the complete stable-ID inventory without external assets' \
  escript "$ROOT/tests/assert_flow.escript" html "$FLOW_LINKED"
if command -v dot >/dev/null 2>&1; then
  assert_file "$FLOW_LINKED/callgraph.svg" 'Graphviz installation produces callgraph SVG'
fi

FLOW_RUNTIME_BUILD="$TMP_ROOT/flow runtime build"
mkdir -p "$FLOW_RUNTIME_BUILD"
cp -- "$FLOW_RUNTIME_SOURCE" "$FLOW_ON_LOAD_SOURCE" "$FLOW_RUNTIME_BUILD/"
erlc +debug_info +no_copt -o "$FLOW_RUNTIME_BUILD" \
  "$FLOW_RUNTIME_BUILD/flow_runtime_fixture.erl" \
  "$FLOW_RUNTIME_BUILD/flow_on_load_fixture.erl"
FLOW_RUNTIME_GRAPH="$TMP_ROOT/flow runtime graph"
assert_success 'static graph prepares every explicitly supplied runtime fixture' \
  "$TOOL" flow --mode static --scope supplied \
    --beam "$FLOW_RUNTIME_BUILD/flow_runtime_fixture.beam" \
    --beam "$FLOW_RUNTIME_BUILD/flow_on_load_fixture.beam" \
    --output "$FLOW_RUNTIME_GRAPH" --allow-otp-major "$otp_major"
FLOW_RUNTIME_GRAPH_SHA_BEFORE=$(sha256sum "$FLOW_RUNTIME_GRAPH/flow-ir.term" | awk '{print $1}')
assert_success 'the documented runtime scenario passes strict validation' \
  "$TOOL" trace-scenario-check --scenario "$FLOW_SCENARIO_SOURCE" \
    --allow-otp-major "$otp_major"
FLOW_RUNTIME_TRACE="$TMP_ROOT/flow runtime trace"
assert_success 'isolated-runtime executes the declarative scenario in a disposable peer' \
  "$TOOL" flow --mode isolated-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --scenario "$FLOW_SCENARIO_SOURCE" --isolation process \
    --output "$FLOW_RUNTIME_TRACE" --allow-otp-major "$otp_major"
assert_file "$FLOW_RUNTIME_TRACE/.beam-flow-trace" 'isolated-runtime commits its trace marker last'
assert_file "$FLOW_RUNTIME_TRACE/trace-manifest.term" 'isolated-runtime writes a trace manifest'
assert_file "$FLOW_RUNTIME_TRACE/events.term" 'isolated-runtime writes its first raw event capture'
assert_file "$FLOW_RUNTIME_TRACE/events.raw.etf" 'isolated-runtime writes length-framed lossless ETF events'
assert_file "$FLOW_RUNTIME_TRACE/events.normalized.jsonl" 'isolated-runtime writes normalized JSONL events'
assert_file "$FLOW_RUNTIME_TRACE/trace-completeness.term" 'isolated-runtime writes trace completeness evidence'
assert_success 'isolated trace proves calls, messages, on_load, assertions, and cleanup' \
  escript "$ROOT/tests/assert_flow.escript" isolated "$FLOW_RUNTIME_TRACE"
assert_success 'raw frames, JSONL records, manifest, and completeness counts reconcile' \
  escript "$ROOT/tests/assert_flow.escript" runtime_stream "$FLOW_RUNTIME_TRACE"
assert_file "$FLOW_RUNTIME_TRACE/runtime-processes.term" 'runtime overlay writes process inventory'
assert_file "$FLOW_RUNTIME_TRACE/runtime-edges.term" 'runtime overlay writes call spawn and message edges'
assert_file "$FLOW_RUNTIME_TRACE/runtime-unmatched.term" 'runtime overlay retains unmatched events'
assert_file "$FLOW_RUNTIME_TRACE/runtime-overlay.term" 'runtime overlay writes its authoritative manifest'
assert_file "$FLOW_RUNTIME_TRACE/runtime.dot" 'runtime overlay writes DOT visualization'
assert_file "$FLOW_RUNTIME_TRACE/timeline.json" 'runtime overlay writes complete JSON timeline'
assert_file "$FLOW_RUNTIME_TRACE/flow.html" 'runtime overlay writes an offline explorer'
if command -v dot >/dev/null 2>&1; then
  assert_file "$FLOW_RUNTIME_TRACE/runtime.svg" 'runtime overlay renders SVG when Graphviz is available'
fi
assert_success 'runtime overlay correlates calls exceptions processes messages and timeline' \
  escript "$ROOT/tests/assert_flow.escript" overlay \
    "$FLOW_RUNTIME_TRACE" "$FLOW_RUNTIME_GRAPH"
FLOW_RUNTIME_GRAPH_SHA_AFTER=$(sha256sum "$FLOW_RUNTIME_GRAPH/flow-ir.term" | awk '{print $1}')
if [[ $FLOW_RUNTIME_GRAPH_SHA_BEFORE == "$FLOW_RUNTIME_GRAPH_SHA_AFTER" ]]; then
  pass 'runtime overlay leaves authoritative static IR byte-identical'
else
  fail 'runtime overlay leaves authoritative static IR byte-identical'
fi
assert_success 'raw trace checker accepts every complete length-framed ETF record' \
  "$TOOL" trace-raw-check --input "$FLOW_RUNTIME_TRACE/events.raw.etf" \
    --allow-otp-major "$otp_major"
TRUNCATED_RAW="$TMP_ROOT/events.truncated.raw.etf"
raw_size=$(wc -c <"$FLOW_RUNTIME_TRACE/events.raw.etf")
head -c "$((raw_size - 1))" "$FLOW_RUNTIME_TRACE/events.raw.etf" >"$TRUNCATED_RAW"
set +e
truncated_raw_output=$("$TOOL" trace-raw-check --input "$TRUNCATED_RAW" \
  --allow-otp-major "$otp_major" 2>&1)
truncated_raw_status=$?
set -e
if [[ $truncated_raw_status -eq 70 && $truncated_raw_output == *truncated_etf_frame* ]]; then
  pass 'raw trace checker rejects a one-byte-truncated final ETF frame'
else
  printf '%s\n' "$truncated_raw_output" >&2
  fail "raw trace checker rejects a one-byte-truncated final ETF frame (status $truncated_raw_status)"
fi
assert_status 73 'isolated-runtime refuses an existing trace directory' \
  "$TOOL" flow --mode isolated-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --scenario "$FLOW_SCENARIO_SOURCE" --isolation process \
    --output "$FLOW_RUNTIME_TRACE" --allow-otp-major "$otp_major"
FLOW_TIMEOUT_SCENARIO="$TMP_ROOT/flow timeout scenario.term"
printf '%s\n' '#{schema => beam_flow_scenario_v1, timeout_ms => 100, steps => [#{op => await, pattern => never_arrives, timeout_ms => 1000}]}.' >"$FLOW_TIMEOUT_SCENARIO"
FLOW_TIMEOUT_TRACE="$TMP_ROOT/flow timeout trace"
set +e
flow_timeout_output=$("$TOOL" flow --mode isolated-runtime \
  --graph "$FLOW_RUNTIME_GRAPH" --scenario "$FLOW_TIMEOUT_SCENARIO" \
  --isolation process --output "$FLOW_TIMEOUT_TRACE" \
  --allow-otp-major "$otp_major" 2>&1)
flow_timeout_status=$?
set -e
if [[ $flow_timeout_status -eq 70 && -f $FLOW_TIMEOUT_TRACE/.beam-flow-trace ]]; then
  pass 'isolated timeout returns failure while committing an explicit partial trace'
else
  printf '%s\n' "$flow_timeout_output" >&2
  fail "isolated timeout returns failure while committing an explicit partial trace (status $flow_timeout_status)"
fi
assert_success 'isolated timeout manifest proves partial state and peer teardown' \
  escript "$ROOT/tests/assert_flow.escript" isolated_partial "$FLOW_TIMEOUT_TRACE"

LIVE_COOKIE_FILE="$TMP_ROOT/live-cookie"
printf 'beam_flow_test_cookie_%s\n' "$$" >"$LIVE_COOKIE_FILE"
chmod 600 "$LIVE_COOKIE_FILE"
LIVE_SHORT_NAME="beam_flow_target_$$_${RANDOM}"
LIVE_READY_FILE="$TMP_ROOT/live-target.node"
LIVE_TARGET_LOG="$TMP_ROOT/live-target.log"
erl -noshell -sname "$LIVE_SHORT_NAME" \
  -setcookie "$(tr -d '\n' <"$LIVE_COOKIE_FILE")" \
  -pa "$FLOW_RUNTIME_BUILD" \
  -eval "ok=flow_runtime_fixture:start_live(), ok=file:write_file(\"$LIVE_READY_FILE\",atom_to_binary(node(),utf8)), receive stop_node -> ok end." \
  >"$LIVE_TARGET_LOG" 2>&1 &
LIVE_TARGET_PID=$!
for _attempt in $(seq 1 100); do
  [[ -s $LIVE_READY_FILE ]] && break
  kill -0 "$LIVE_TARGET_PID" 2>/dev/null || break
  sleep 0.1
done
if [[ -s $LIVE_READY_FILE ]]; then
  LIVE_TARGET_NODE=$(<"$LIVE_READY_FILE")
  pass 'disposable live target starts with an exact distributed node identity'
else
  sed -n '1,80p' "$LIVE_TARGET_LOG" >&2 || true
  fail 'disposable live target starts with an exact distributed node identity'
  LIVE_TARGET_NODE="missing@target"
fi

LIVE_COOKIE_PERMISSIVE="$TMP_ROOT/live-cookie-permissive"
cp -- "$LIVE_COOKIE_FILE" "$LIVE_COOKIE_PERMISSIVE"
chmod 644 "$LIVE_COOKIE_PERMISSIVE"
LIVE_COOKIE_SYMLINK="$TMP_ROOT/live-cookie-symlink"
ln -s "$LIVE_COOKIE_FILE" "$LIVE_COOKIE_SYMLINK"
assert_status 66 'live mode rejects a missing cookie file' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$TMP_ROOT/missing-cookie" \
    --output "$TMP_ROOT/live missing cookie" --allow-otp-major "$otp_major"
assert_status 65 'live mode rejects a permissive cookie file' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_PERMISSIVE" \
    --output "$TMP_ROOT/live permissive cookie" --allow-otp-major "$otp_major"
assert_status 65 'live mode rejects a symlink cookie file' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_SYMLINK" \
    --output "$TMP_ROOT/live symlink cookie" --allow-otp-major "$otp_major"
assert_status 64 'live mode rejects a zero duration bound' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --duration 0 --output "$TMP_ROOT/live zero duration"
assert_status 64 'live mode rejects a zero event bound' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --max-events 0 --output "$TMP_ROOT/live zero events"
assert_status 64 'live mode rejects a zero byte bound' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --max-bytes 0 --output "$TMP_ROOT/live zero bytes"
assert_status 70 'live mode rejects an unreachable exact node without output' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "absent_$$_${RANDOM}@$(hostname -s)" \
    --cookie-file "$LIVE_COOKIE_FILE" --duration 1 \
    --output "$TMP_ROOT/live unreachable" --allow-otp-major "$otp_major"

LIVE_DURATION_TRACE="$TMP_ROOT/live duration trace"
assert_success 'bounded live trace stops at its duration trigger' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend auto \
    --duration 1 --max-events 1000000 --max-bytes 100000000 \
    --output "$LIVE_DURATION_TRACE" --allow-otp-major "$otp_major"
assert_success 'duration live trace preserves code identity and cleans its session' \
  escript "$ROOT/tests/assert_flow.escript" live "$LIVE_DURATION_TRACE" \
    duration "$LIVE_TARGET_NODE"

LIVE_EVENT_TRACE="$TMP_ROOT/live event trace"
assert_success 'bounded live trace stops at its event-count trigger' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend session \
    --duration 10 --max-events 5 --max-bytes 100000000 \
    --output "$LIVE_EVENT_TRACE" --allow-otp-major "$otp_major"
assert_success 'event-count live trace records its exact trigger and cleanup' \
  escript "$ROOT/tests/assert_flow.escript" live "$LIVE_EVENT_TRACE" \
    max_events "$LIVE_TARGET_NODE"

LIVE_BYTE_TRACE="$TMP_ROOT/live byte trace"
assert_success 'bounded live trace stops at its byte trigger' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend session \
    --duration 10 --max-events 1000000 --max-bytes 1 \
    --output "$LIVE_BYTE_TRACE" --allow-otp-major "$otp_major"
assert_success 'byte-bounded live trace records its exact trigger and cleanup' \
  escript "$ROOT/tests/assert_flow.escript" live "$LIVE_BYTE_TRACE" \
    max_bytes "$LIVE_TARGET_NODE"

LIVE_DBG_TRACE="$TMP_ROOT/live dbg trace"
assert_success 'explicit dbg backend runs in its own bounded session' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend dbg \
    --duration 10 --max-events 5 --max-bytes 100000000 \
    --output "$LIVE_DBG_TRACE" --allow-otp-major "$otp_major"
assert_success 'dbg backend proves isolated-session cleanup and code identity' \
  escript "$ROOT/tests/assert_flow.escript" live_backend "$LIVE_DBG_TRACE" \
    max_events "$LIVE_TARGET_NODE" dbg

LIVE_LEGACY_TRACE="$TMP_ROOT/live legacy trace"
assert_success 'legacy test target starts with unrelated trace state' \
  erl -noshell -sname "beam_flow_legacy_setup_$$_${RANDOM}" \
    -setcookie "$(tr -d '\n' <"$LIVE_COOKIE_FILE")" \
    -eval "ok=erpc:call('$LIVE_TARGET_NODE',flow_runtime_fixture,start_legacy_state,[]),halt()."
assert_success 'explicit acknowledged legacy backend captures a bounded trace' \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend legacy \
    --allow-legacy-live-trace --acknowledge-live-risk \
    --duration 10 --max-events 5 --max-bytes 100000000 \
    --output "$LIVE_LEGACY_TRACE" --allow-otp-major "$otp_major"
assert_success 'legacy backend proves owned-state restoration and code identity' \
  escript "$ROOT/tests/assert_flow.escript" live_backend \
    "$LIVE_LEGACY_TRACE" max_events "$LIVE_TARGET_NODE" legacy
assert_success 'legacy backend restores pre-existing flags tracer and pattern' \
  erl -noshell -sname "beam_flow_legacy_verify_$$_${RANDOM}" \
    -setcookie "$(tr -d '\n' <"$LIVE_COOKIE_FILE")" \
    -eval "ok=erpc:call('$LIVE_TARGET_NODE',flow_runtime_fixture,assert_legacy_state,[]),ok=erpc:call('$LIVE_TARGET_NODE',flow_runtime_fixture,clear_legacy_state,[]),halt()."

LIVE_UNBOUNDED_TRACE="$TMP_ROOT/live unbounded signal trace"
LIVE_UNBOUNDED_LOG="$TMP_ROOT/live-unbounded.log"
set +e
timeout --foreground --preserve-status --signal=INT --kill-after=15s 2s \
  "$TOOL" flow --mode live-runtime --graph "$FLOW_RUNTIME_GRAPH" \
    --node "$LIVE_TARGET_NODE" --cookie-file "$LIVE_COOKIE_FILE" \
    --process registered:beam_flow_live_worker --trace-backend session \
    --unbounded-live-trace --acknowledge-live-risk \
    --output "$LIVE_UNBOUNDED_TRACE" --allow-otp-major "$otp_major" \
    >"$LIVE_UNBOUNDED_LOG" 2>&1
LIVE_UNBOUNDED_STATUS=$?
set -e
if [[ $LIVE_UNBOUNDED_STATUS -eq 70 && -f $LIVE_UNBOUNDED_TRACE/.beam-flow-trace ]]; then
  pass 'SIGINT commits an explicit partial unbounded trace and returns failure'
else
  sed -n '1,100p' "$LIVE_UNBOUNDED_LOG" >&2 || true
  fail "SIGINT commits an explicit partial unbounded trace and returns failure (status $LIVE_UNBOUNDED_STATUS)"
fi
assert_success 'unbounded SIGINT trace drains, cleans up, and preserves its target' \
  escript "$ROOT/tests/assert_flow.escript" live_signal \
    "$LIVE_UNBOUNDED_TRACE" "$LIVE_TARGET_NODE"
assert_success 'live target remains responsive after every controller exits' \
  erl -noshell -sname "beam_flow_probe_$$_${RANDOM}" \
    -setcookie "$(tr -d '\n' <"$LIVE_COOKIE_FILE")" \
    -eval "pong=net_adm:ping('$LIVE_TARGET_NODE'),halt()."

FLOW_DIRECTORY="$TMP_ROOT/flow immediate directory"
assert_success 'supplied scope discovers immediate BEAM children only' \
  "$TOOL" flow --mode static --scope supplied --beam-dir "$FLOW_CROSS_BUILD" \
    --output "$FLOW_DIRECTORY" --allow-otp-major "$otp_major"
assert_success 'supplied directory scope commits both modules' \
  escript "$ROOT/tests/assert_flow.escript" module_count "$FLOW_DIRECTORY" 2

FLOW_TREE_ROOT="$TMP_ROOT/flow tree root"
mkdir -p "$FLOW_TREE_ROOT/a" "$FLOW_TREE_ROOT/nested/b"
cp -- "$FLOW_CROSS_BUILD/flow_cross_a.beam" "$FLOW_TREE_ROOT/a/"
cp -- "$FLOW_CROSS_BUILD/flow_cross_b.beam" "$FLOW_TREE_ROOT/nested/b/"
FLOW_TREE="$TMP_ROOT/flow tree"
assert_success 'tree scope recursively discovers only explicit roots' \
  "$TOOL" flow --mode static --scope tree --beam-dir "$FLOW_TREE_ROOT" \
    --output "$FLOW_TREE" --allow-otp-major "$otp_major"
assert_success 'tree scope commits both recursively discovered modules' \
  escript "$ROOT/tests/assert_flow.escript" module_count "$FLOW_TREE" 2

QUERY_CALLEES="$TMP_ROOT/query callees.term"
"$TOOL" flow-query --graph "$FLOW_LINKED" --from flow_cross_a:start/1 \
  --direction callees --max-depth 2 --format term \
  --allow-otp-major "$otp_major" >"$QUERY_CALLEES"
assert_success 'flow-query traverses committed callees without reanalysis' \
  escript "$ROOT/tests/assert_flow.escript" query "$QUERY_CALLEES" callees 2
QUERY_ZERO="$TMP_ROOT/query zero.term"
"$TOOL" flow-query --graph "$FLOW_LINKED" --from flow_cross_a:start/1 \
  --direction both --max-depth 0 --format term \
  --allow-otp-major "$otp_major" >"$QUERY_ZERO"
assert_success 'flow-query supports a depth-zero origin-only view' \
  escript "$ROOT/tests/assert_flow.escript" query "$QUERY_ZERO" both 0
QUERY_JSON="$TMP_ROOT/query.json"
"$TOOL" flow-query --graph "$FLOW_LINKED" --from flow_cross_a:start/1 \
  --direction callees --max-depth 1 --format json \
  --allow-otp-major "$otp_major" >"$QUERY_JSON"
assert_success 'flow-query JSON output is normalized and parseable' \
  escript "$ROOT/tests/assert_flow.escript" query_json "$QUERY_JSON"
assert_status 70 'flow-query rejects an unknown origin' \
  "$TOOL" flow-query --graph "$FLOW_LINKED" --from absent_module:absent/0 \
    --direction both --max-depth 1 --format term --allow-otp-major "$otp_major"
GZIP_INPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.beam.gz"
GZIP_OUTPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.unpacked.beam"
gzip -c -- "$INPUT" >"$GZIP_INPUT"
assert_success 'unpack expands an outer-gzip BEAM without changing its bytes' "$TOOL" unpack --input "$GZIP_INPUT" --output "$GZIP_OUTPUT" --allow-otp-major "$otp_major"
if cmp -s -- "$INPUT" "$GZIP_OUTPUT"; then pass 'unpack output exactly matches the original FOR1 BEAM'; else fail 'unpack output exactly matches the original FOR1 BEAM'; fi
assert_success 'doctor accepts the unpacked FOR1 BEAM' "$TOOL" doctor --input "$GZIP_OUTPUT" --allow-otp-major "$otp_major"
assert_status 73 'unpack refuses an existing output' "$TOOL" unpack --input "$GZIP_INPUT" --output "$GZIP_OUTPUT" --allow-otp-major "$otp_major"
BAD_GZIP="$TMP_ROOT/input with spaces/truncated.beam.gz"
head -c -4 "$GZIP_INPUT" >"$BAD_GZIP"
assert_status 70 'unpack rejects a truncated gzip stream' "$TOOL" unpack --input "$BAD_GZIP" --output "$TMP_ROOT/truncated-output.beam" --allow-otp-major "$otp_major"
ln -s "$GZIP_INPUT" "$TMP_ROOT/gzip-symlink"
assert_status 65 'unpack rejects a symlink input' "$TOOL" unpack --input "$TMP_ROOT/gzip-symlink" --output "$TMP_ROOT/symlink-output.beam" --allow-otp-major "$otp_major"
KEY1_FILE="$TMP_ROOT/aes-key1"
KEY2_FILE="$TMP_ROOT/aes-key2"
WRONG_KEY_FILE="$TMP_ROOT/aes-wrong-key"
printf '%s\n' '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' >"$KEY1_FILE"
printf '%s\n' 'FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100' >"$KEY2_FILE"
printf '%s\n' '10112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF' >"$WRONG_KEY_FILE"
chmod 600 "$KEY1_FILE" "$KEY2_FILE" "$WRONG_KEY_FILE" "$AES_FIXTURE_BUILDER"
PACKED_INPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.packed.beam"
EXPECTED_DECRYPTED="$TMP_ROOT/input with spaces/beam_patch_fixture.expected.beam"
escript "$AES_FIXTURE_BUILDER" "$INPUT" "$PACKED_INPUT" "$EXPECTED_DECRYPTED" "$KEY1_FILE" "$KEY2_FILE"
DECRYPTED_OUTPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.decrypted.beam"
assert_success 'decrypt-aes reconstructs a structurally valid BEAM with both selected keys' "$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$DECRYPTED_OUTPUT" --key1-file "$KEY1_FILE" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major"
if cmp -s -- "$EXPECTED_DECRYPTED" "$DECRYPTED_OUTPUT"; then pass 'decrypt-aes output exactly matches the synthetic unpacked BEAM'; else fail 'decrypt-aes output exactly matches the synthetic unpacked BEAM'; fi
assert_success 'doctor accepts the structurally validated decrypted BEAM' "$TOOL" doctor --input "$DECRYPTED_OUTPUT" --allow-otp-major "$otp_major"
assert_status 73 'decrypt-aes refuses an existing output' "$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$DECRYPTED_OUTPUT" --key1-file "$KEY1_FILE" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major"
WRONG_OUTPUT="$TMP_ROOT/wrong-key-output.beam"
set +e
wrong_key_output=$("$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$WRONG_OUTPUT" --key1-file "$WRONG_KEY_FILE" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major" 2>&1)
wrong_key_status=$?
set -e
if [[ $wrong_key_status -eq 70 && $wrong_key_output == *invalid_decrypted_candidate* && ${#wrong_key_output} -lt 4000 ]]; then
  pass 'decrypt-aes rejects a wrong key with a concise sanitized error'
else
  printf '%s\n' "$wrong_key_output" >&2
  fail 'decrypt-aes rejects a wrong key with a concise sanitized error'
fi
if [[ ! -e $WRONG_OUTPUT ]]; then pass 'wrong AES key leaves no output'; else fail 'wrong AES key leaves no output'; fi
PERMISSIVE_KEY="$TMP_ROOT/permissive-key"
cp -- "$KEY1_FILE" "$PERMISSIVE_KEY"
chmod 644 "$PERMISSIVE_KEY"
assert_status 65 'decrypt-aes rejects a group-or-world-accessible key file' "$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$TMP_ROOT/permissive-output.beam" --key1-file "$PERMISSIVE_KEY" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major"
MALFORMED_KEY="$TMP_ROOT/malformed-key"
printf '%s\n' 'not-64-hex-characters' >"$MALFORMED_KEY"
chmod 600 "$MALFORMED_KEY"
assert_status 70 'decrypt-aes rejects malformed key content without printing it' "$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$TMP_ROOT/malformed-output.beam" --key1-file "$MALFORMED_KEY" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major"
ln -s "$KEY1_FILE" "$TMP_ROOT/key-symlink"
assert_status 65 'decrypt-aes rejects a symlink key file' "$TOOL" decrypt-aes --input "$PACKED_INPUT" --output "$TMP_ROOT/key-symlink-output.beam" --key1-file "$TMP_ROOT/key-symlink" --key2-file "$KEY2_FILE" --allow-otp-major "$otp_major"
ARBITRARY_INPUT="$TMP_ROOT/input with spaces/beam_patch_fixture.beam.orig"
cp -- "$INPUT" "$ARBITRARY_INPUT"
HELPER_PREFLIGHT="$TMP_ROOT/embedded-helper.escript"
awk '/^#!\/usr\/bin\/env escript$/{inside=1} inside && /^ESCRIPT$/{exit} inside{print}' "$TOOL" >"$HELPER_PREFLIGHT"
chmod 700 "$HELPER_PREFLIGHT"
assert_status 70 'embedded helper compiles before workflow tests' escript "$HELPER_PREFLIGHT"
SYNTHETIC_FORMS="$TMP_ROOT/synthetic-forms.term"
assert_success 'synthetic symbolic-form analyzer accepts call_fun2 and make_fun2' escript "$HELPER_PREFLIGHT" forms_fixture "$SYNTHETIC_FORMS"
synthetic_forms_output=$(erl -noshell -eval "{ok,[Report]}=file:consult(\"$SYNTHETIC_FORMS\"), Dynamic=maps:get(dynamic_calls,Report), Dependencies=maps:get(dependencies,Report), true=lists:any(fun(#{instruction := {apply,1}, resolution := #{certainty := exact, target := {erlang,length,1}}}) -> true; (_) -> false end,Dynamic), true=lists:any(fun(#{instruction := {apply_last,2}, resolution := #{certainty := exact, target := {erlang,element,2}}}) -> true; (_) -> false end,Dynamic), true=lists:any(fun(#{kind := call_fun2, resolution := #{certainty := exact, target := {synthetic,target,1}}}) -> true; (_) -> false end,Dynamic), true=lists:any(fun(#{fun_references := Refs}) -> lists:any(fun(#{target := {synthetic,target,1}})->true;(_)->false end,Refs); (_) -> false end,Dependencies), io:format(\"synthetic forms ok~n\"), halt()." 2>&1)
assert_contains 'synthetic forms ok' "$synthetic_forms_output" 'synthetic forms exercise positional apply and call_fun2 analysis'
NORMALIZED_FORMS="$TMP_ROOT/normalized-local-calls.term"
assert_success 'synthetic local call forms normalize to entry labels' escript "$HELPER_PREFLIGHT" normalization_fixture "$NORMALIZED_FORMS"
normalized_forms_output=$(erl -noshell -eval "{ok,[Functions]}=file:consult(\"$NORMALIZED_FORMS\"), true=lists:any(fun({function,synthetic_call,0,20,Instructions})->lists:member({call,1,{f,10}},Instructions);(_)->false end,Functions), true=lists:any(fun({function,synthetic_call_only,0,30,Instructions})->lists:member({call_only,1,{f,10}},Instructions);(_)->false end,Functions), true=lists:any(fun({function,synthetic_call_last,0,40,Instructions})->lists:member({call_last,1,{f,10},0},Instructions);(_)->false end,Functions), true=lists:any(fun({function,synthetic_call_fun2,0,50,Instructions})->lists:member({call_fun2,{f,10},1,{tr,{x,1},{t_fun,1,{synthetic_target,1},any}}},Instructions);(_)->false end,Functions), io:format(\"local call normalization ok~n\"), halt()." 2>&1)
assert_contains 'local call normalization ok' "$normalized_forms_output" 'normalizer rewrites local calls and fills only lost call_fun2 targets'
set +e
missing_target_output=$(escript "$HELPER_PREFLIGHT" normalization_missing_target 2>&1)
missing_target_status=$?
set -e
if [[ $missing_target_status -eq 70 && $missing_target_output == *missing_local_target* ]]; then
  pass 'normalizer rejects an absent local call target clearly'
else
  printf '%s\n' "$missing_target_output" >&2
  fail "normalizer rejects an absent local call target clearly (expected status 70 and missing_local_target)"
fi
set +e
missing_fun_label_output=$(escript "$HELPER_PREFLIGHT" normalization_missing_fun_label 2>&1)
missing_fun_label_status=$?
set -e
if [[ $missing_fun_label_status -eq 70 && $missing_fun_label_output == *missing_fun_entry_label* ]]; then
  pass 'normalizer rejects an absent call_fun2 entry label clearly'
else
  printf '%s\n' "$missing_fun_label_output" >&2
  fail "normalizer rejects an absent call_fun2 entry label clearly (expected status 70 and missing_fun_entry_label)"
fi
set +e
invalid_fun_arity_output=$(escript "$HELPER_PREFLIGHT" normalization_invalid_fun_arity 2>&1)
invalid_fun_arity_status=$?
set -e
if [[ $invalid_fun_arity_status -eq 70 && $invalid_fun_arity_output == *invalid_fun_target_arity* ]]; then
  pass 'normalizer rejects call_fun2 arity exceeding its target clearly'
else
  printf '%s\n' "$invalid_fun_arity_output" >&2
  fail "normalizer rejects call_fun2 arity exceeding its target clearly (expected status 70 and invalid_fun_target_arity)"
fi
ln -s "$INPUT" "$TMP_ROOT/symlink.beam"

assert_status 65 'extract rejects a symlink input' "$TOOL" extract --input "$TMP_ROOT/symlink.beam" --workspace "$TMP_ROOT/symlink workspace"
assert_success 'doctor accepts a readable BEAM with an arbitrary extension' "$TOOL" doctor --input "$ARBITRARY_INPUT" --allow-otp-major "$otp_major"
mkdir "$TMP_ROOT/unmarked workspace"
assert_status 73 'extract refuses an existing unmarked workspace' "$TOOL" extract --input "$INPUT" --workspace "$TMP_ROOT/unmarked workspace"
POISONED_WORKSPACE="$TMP_ROOT/poisoned marked workspace"
mkdir "$POISONED_WORKSPACE"
: >"$POISONED_WORKSPACE/.beam-patch-workspace"
printf '#!/usr/bin/env bash\nprintf poisoned-helper >&2\nexit 99\n' >"$POISONED_WORKSPACE/.beam_patch_helper.escript"
chmod 700 "$POISONED_WORKSPACE/.beam_patch_helper.escript"
assert_status 73 'extract refuses a poisoned incomplete marked workspace without running its helper' "$TOOL" extract --input "$INPUT" --workspace "$POISONED_WORKSPACE" --allow-otp-major "$otp_major"

WORKSPACE="$TMP_ROOT/workspace with spaces"
assert_success 'extract accepts paths containing spaces' "$TOOL" extract --input "$INPUT" --workspace "$WORKSPACE" --allow-otp-major "$otp_major"
assert_file "$WORKSPACE/.beam-patch-workspace" 'extract creates workspace marker'
assert_file "$WORKSPACE/original.beam" 'extract saves immutable original copy'
assert_file "$WORKSPACE/original.sha256" 'extract records source hash'
assert_file "$WORKSPACE/manifest.term" 'extract writes manifest'
assert_file "$WORKSPACE/disassembly.term" 'extract writes disassembly'
assert_file "$WORKSPACE/editable.S" 'extract writes editable assembly'
assert_file "$WORKSPACE/extra_chunks.term" 'extract writes extra chunks'
assert_file "$WORKSPACE/functions.term" 'extract writes every-function inventory'
assert_file "$WORKSPACE/dependencies.term" 'extract writes every-function dependency inventory'
assert_file "$WORKSPACE/dynamic_calls.term" 'extract writes complete dynamic-call inventory'
set +e
complete_status_output=$("$TOOL" workspace-status --workspace "$WORKSPACE" --input "$INPUT" 2>&1)
complete_status=$?
set -e
if [[ $complete_status -eq 0 && $complete_status_output == *'state=extracted'* && $complete_status_output == *'input_match=yes'* ]]; then
  pass 'workspace-status validates a complete extracted workspace and its input'
else
  printf '%s\n' "$complete_status_output" >&2
  fail "workspace-status validates a complete extracted workspace and its input (status $complete_status)"
fi
set +e
reuse_extract_output=$("$TOOL" extract --input "$INPUT" --workspace "$WORKSPACE" --allow-otp-major "$otp_major" 2>&1)
reuse_extract_status=$?
set -e
if [[ $reuse_extract_status -eq 0 && $reuse_extract_output == *'workspace already complete'* ]]; then
  pass 'extract safely reuses an already complete matching workspace'
else
  printf '%s\n' "$reuse_extract_output" >&2
  fail "extract safely reuses an already complete matching workspace (status $reuse_extract_status)"
fi
set +e
manifest_versions_output=$(erl -noshell -eval "{ok,[Manifest]}=file:consult(\"$WORKSPACE/manifest.term\"), true=maps:get(otp_release,Manifest)=:=erlang:system_info(otp_release), true=maps:get(erts_version,Manifest)=:=erlang:system_info(version), true=maps:get(erl_path,Manifest)=:=\"$expected_erl_path\", true=maps:get(escript_path,Manifest)=:=\"$expected_escript_path\", io:format(\"manifest versions ok~n\"), halt()." 2>&1)
manifest_versions_status=$?
set -e
if [[ $manifest_versions_status -eq 0 ]]; then
  assert_contains 'manifest versions ok' "$manifest_versions_output" 'manifest records exact current OTP and ERTS versions'
else
  printf '%s\n' "$manifest_versions_output" >&2
  fail "manifest records exact current OTP and ERTS versions (status $manifest_versions_status)"
fi
set +e
local_call_forms_output=$(erl -noshell -eval "{ok,[{beam_file,_,_,_,_,Functions}]}=file:consult(\"$WORKSPACE/disassembly.term\"), true=lists:any(fun({function,local_call,1,_,Instructions})->lists:any(fun({call,1,{beam_patch_fixture,local_target,1}})->true;(_)->false end,Instructions);(_)->false end,Functions), true=lists:any(fun({function,local_tail_call,1,_,Instructions})->lists:any(fun({call_only,1,{beam_patch_fixture,local_target,1}})->true;({call_last,1,{beam_patch_fixture,local_target,1},_})->true;(_)->false end,Instructions);(_)->false end,Functions), io:format(\"local call forms ok~n\"), halt()." 2>&1)
local_call_forms_status=$?
set -e
if [[ $local_call_forms_status -eq 0 ]]; then
  assert_contains 'local call forms ok' "$local_call_forms_output" 'fixture emits local ordinary and tail call targets in disassembly'
else
  printf '%s\n' "$local_call_forms_output" >&2
  fail "fixture emits local ordinary and tail call targets in disassembly (status $local_call_forms_status)"
fi
set +e
bif_nofail_output=$(erl -noshell -eval "{ok,[{beam_file,_,_,_,_,RawFunctions}]}=file:consult(\"$WORKSPACE/disassembly.term\"), {ok,[{beam_patch_assembly,1,#{functions := EditableFunctions}}]}=file:consult(\"$WORKSPACE/editable.S\"), true=lists:any(fun({function,self_value,0,_,Instructions})->lists:any(fun({bif,self,nofail,[],{x,_}})->true;(_)->false end,Instructions);(_)->false end,RawFunctions), true=lists:any(fun({function,self_value,0,_,Instructions})->lists:any(fun({bif,self,{f,0},[],{x,_}})->true;(_)->false end,Instructions);(_)->false end,EditableFunctions), io:format(\"bif nofail normalization ok~n\"), halt()." 2>&1)
bif_nofail_status=$?
set -e
if [[ $bif_nofail_status -eq 0 ]]; then
  assert_contains 'bif nofail normalization ok' "$bif_nofail_output" 'normalizer translates only raw nofail self BIFs for beam_asm'
else
  printf '%s\n' "$bif_nofail_output" >&2
  fail "normalizer translates raw nofail self BIFs for beam_asm (status $bif_nofail_status)"
fi
set +e
inventory_output=$(erl -noshell -eval "{ok,[{beam_patch_functions,1,Functions}]}=file:consult(\"$WORKSPACE/functions.term\"), {ok,[{beam_patch_dependencies,1,Dependencies}]}=file:consult(\"$WORKSPACE/dependencies.term\"), {ok,[{beam_patch_dynamic_calls,1,DynamicCalls}]}=file:consult(\"$WORKSPACE/dynamic_calls.term\"), Checks=[{cardinality,length(Functions)=:=length(Dependencies)},{instruction_count,lists:all(fun(#{instruction_count := Count, locations := Locations}) -> is_integer(Count) andalso Count > 0 andalso is_list(Locations); (_) -> false end, Functions)},{location_metadata,lists:any(fun(#{locations := [#{metadata := _}|_]}) -> true; (_) -> false end, Functions)},{value_record,lists:any(fun(#{name := value, arity := 0, entry_label := 2, labels := [_|_]}) -> true; (_) -> false end, Functions)},{empty_dependency,lists:any(fun(#{name := value, arity := 0, local_calls := [], external_calls := [], bifs := [], fun_references := [], unresolved_dynamic_calls := []}) -> true; (_) -> false end, Dependencies)},{static_exact,lists:any(fun(#{caller := static_apply, resolution := #{certainty := exact, target := {erlang,length,1}}}) -> true; (_) -> false end, DynamicCalls)},{known_fun_exact,lists:any(fun(#{caller := known_fun, resolution := #{certainty := exact, target := {beam_patch_fixture,echo,1}}}) -> true; (_) -> false end, DynamicCalls)},{dynamic_unresolved,lists:any(fun(#{caller := fully_dynamic_apply, resolution := #{certainty := unresolved, reason := _}}) -> true; (_) -> false end, DynamicCalls)},{partial,lists:any(fun(#{caller := partial_apply, resolution := #{certainty := partial, available := #{module := erlang, argument_arity := 1}}}) -> true; (_) -> false end, DynamicCalls)},{branch_conservative,lists:any(fun(#{caller := branch_apply, resolution := #{certainty := Certainty}}) when Certainty =/= exact -> true; (_) -> false end, DynamicCalls)},{call_fun,lists:any(fun(#{caller := dynamic_fun_call, kind := call_fun}) -> true; (_) -> false end, DynamicCalls)}], lists:foreach(fun({Name,Value}) -> io:format(\"inventory_check ~p=~p~n\",[Name,Value]) end,Checks), true=lists:all(fun({_Name,Value})->Value end,Checks), io:format(\"inventory ok~n\"), halt()." 2>&1)
inventory_status=$?
set -e
if [[ $inventory_status -eq 0 ]]; then
  assert_contains 'inventory ok' "$inventory_output" 'inventories describe every benign fixture function without filters'
else
  printf '%s\n' "$inventory_output" >&2
  fail "inventories preserve cardinality, metadata, and conservative dynamic resolution (status $inventory_status)"
fi
BEAM_FORMS_DIR="$TMP_ROOT/actual beam forms"
mkdir "$BEAM_FORMS_DIR"
cp -- "$FIXTURE_SOURCE" "$BEAM_FORMS_DIR/beam_patch_fixture.erl"
erlc +debug_info -o "$BEAM_FORMS_DIR" "$BEAM_FORMS_DIR/beam_patch_fixture.erl"
BEAM_FORMS_INPUT="$BEAM_FORMS_DIR/beam_patch_fixture.beam"
BEAM_FORMS_WORKSPACE="$TMP_ROOT/actual beam forms workspace"
assert_success 'extract accepts OTP-emitted BEAM apply forms' "$TOOL" extract --input "$BEAM_FORMS_INPUT" --workspace "$BEAM_FORMS_WORKSPACE" --allow-otp-major "$otp_major"
set +e
beam_forms_output=$(erl -noshell -eval "{beam_file,_,_,_,_,Functions}=beam_disasm:file(\"$BEAM_FORMS_INPUT\"), true=lists:any(fun({function,beam_apply,3,_,Instructions}) -> lists:any(fun({apply,_})->true;(_)->false end,Instructions); (_) -> false end,Functions), true=lists:any(fun({function,beam_apply_last,3,_,Instructions}) -> lists:any(fun({apply_last,_,_})->true;(_)->false end,Instructions); (_) -> false end,Functions), {ok,[{beam_patch_dynamic_calls,1,Dynamic}]}=file:consult(\"$BEAM_FORMS_WORKSPACE/dynamic_calls.term\"), true=lists:any(fun(#{caller := beam_apply,instruction := {apply,1},resolution := #{certainty := partial,available := #{argument_arity := 1}}})->true;(_)->false end,Dynamic), true=lists:any(fun(#{caller := beam_apply_last,instruction := {apply_last,1},resolution := #{certainty := partial,available := #{argument_arity := 1}}})->true;(_)->false end,Dynamic), io:format(\"actual beam forms ok~n\"),halt()." 2>&1)
beam_forms_status=$?
set -e
if [[ $beam_forms_status -eq 0 ]]; then
  assert_contains 'actual beam forms ok' "$beam_forms_output" 'OTP 27 BEAM apply and apply_last preserve positional partial facts'
else
  printf '%s\n' "$beam_forms_output" >&2
  fail "OTP 27 BEAM apply and apply_last positional analysis (status $beam_forms_status)"
fi
ARBITRARY_WORKSPACE="$TMP_ROOT/arbitrary extension workspace"
assert_success 'extract accepts a readable BEAM with .beam.orig suffix' "$TOOL" extract --input "$ARBITRARY_INPUT" --workspace "$ARBITRARY_WORKSPACE" --allow-otp-major "$otp_major"
assert_success 'roundtrip accepts a readable BEAM with .beam.orig suffix' "$TOOL" roundtrip --input "$ARBITRARY_INPUT" --workspace "$ARBITRARY_WORKSPACE" --allow-otp-major "$otp_major"
assert_success 'verify accepts arbitrary-extension original and candidate' "$TOOL" verify --original "$ARBITRARY_INPUT" --candidate "$ARBITRARY_WORKSPACE/roundtrip.beam" --allow-otp-major "$otp_major"
[[ $(sha256sum "$INPUT" | awk '{print $1}') == "$INPUT_SHA" ]] && pass 'extract does not alter input' || fail 'extract does not alter input'

assert_status 66 'neutral line canary refuses a workspace without roundtrip proof' "$TOOL" neutral-line-canary --workspace "$WORKSPACE" --entry-label 1 --output "$TMP_ROOT/preproof canary.S" --allow-otp-major "$otp_major"
assert_status 66 'rebuild refuses a workspace without roundtrip proof' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --output "$TMP_ROOT/preproof candidate.beam" --allow-otp-major "$otp_major"
assert_success 'roundtrip rebuilds unchanged benign assembly before edits' "$TOOL" roundtrip --input "$INPUT" --workspace "$WORKSPACE" --allow-otp-major "$otp_major"
assert_file "$WORKSPACE/roundtrip.beam" 'roundtrip writes a candidate'
assert_file "$WORKSPACE/.roundtrip-verified.term" 'roundtrip writes provenance proof'
set +e
proof_output=$(erl -noshell -eval "{ok,[{beam_patch_roundtrip_verified,1,Proof}]}=file:consult(\"$WORKSPACE/.roundtrip-verified.term\"), true=maps:get(original_sha256,Proof)=:=hd(string:tokens(os:cmd(\"sha256sum '$WORKSPACE/original.beam'\"),\" \\n\")), true=maps:get(editable_sha256,Proof)=:=hd(string:tokens(os:cmd(\"sha256sum '$WORKSPACE/editable.S'\"),\" \\n\")), true=maps:get(extra_chunks_sha256,Proof)=:=hd(string:tokens(os:cmd(\"sha256sum '$WORKSPACE/extra_chunks.term'\"),\" \\n\")), true=maps:get(roundtrip_sha256,Proof)=:=hd(string:tokens(os:cmd(\"sha256sum '$WORKSPACE/roundtrip.beam'\"),\" \\n\")), true=is_atom(maps:get(module,Proof)), true=is_list(maps:get(otp_release,Proof)), true=is_list(maps:get(erts_version,Proof)), true=maps:get(erl_path,Proof)=:=\"$expected_erl_path\", true=maps:get(escript_path,Proof)=:=\"$expected_escript_path\", io:format(\"roundtrip proof ok~n\"), halt()." 2>&1)
proof_status=$?
set -e
if [[ $proof_status -eq 0 ]]; then
  assert_contains 'roundtrip proof ok' "$proof_output" 'roundtrip proof hashes and runtime versions match workspace'
else
  printf '%s\n' "$proof_output" >&2
  fail "roundtrip proof hashes and runtime versions match workspace (status $proof_status)"
fi

STRUCTURED_FUNCTION="$TMP_ROOT/isolated function.term"
STRUCTURED_ASSEMBLY="$TMP_ROOT/structurally edited.S"
STRUCTURED_BEAM="$TMP_ROOT/structurally edited.beam"
VALUE_LABEL=$(erl -noshell -eval "{ok,[{beam_patch_assembly,1,#{functions := Fs}}]}=file:consult(\"$WORKSPACE/editable.S\"), [{function,value,0,L,_}]=[F || F={function,value,0,_,_} <- Fs], io:format(\"~B\",[L]), halt().")
assert_success 'export-function writes one independently consultable function term' "$TOOL" export-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --entry-label "$VALUE_LABEL" --output "$STRUCTURED_FUNCTION" --allow-otp-major "$otp_major"
assert_success 'exported function wrapper binds identity labels and source digest' \
  escript "$PATCH_VARIANT_BUILDER" "$STRUCTURED_FUNCTION" "$TMP_ROOT"
sed 's/original_value/structured_value/g' "$STRUCTURED_FUNCTION" >"$TMP_ROOT/isolated function edited.term"
assert_success 'replace-function parses, identity-checks, splices, and assembles before writing' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/isolated function edited.term" --output "$STRUCTURED_ASSEMBLY" --allow-otp-major "$otp_major"
assert_success 'validate-assembly parse-checks and assembles the structurally edited term' "$TOOL" validate-assembly --workspace "$WORKSPACE" --assembly "$STRUCTURED_ASSEMBLY" --allow-otp-major "$otp_major"
assert_success 'rebuild accepts the structurally produced assembly' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$STRUCTURED_ASSEMBLY" --output "$STRUCTURED_BEAM" --allow-otp-major "$otp_major"
structured_runtime_output=$(erl -noshell -eval "{ok,B}=file:read_file(\"$STRUCTURED_BEAM\"), {module,beam_patch_fixture}=code:load_binary(beam_patch_fixture,\"$STRUCTURED_BEAM\",B), structured_value=beam_patch_fixture:value(), io:format(\"structured runtime ok~n\"), halt()." 2>&1)
assert_contains 'structured runtime ok' "$structured_runtime_output" 'function-level replacement preserves a usable BEAM'

FROM_TERM="$TMP_ROOT/from literal.term"
TO_TERM="$TMP_ROOT/to literal.term"
REWRITTEN_ASSEMBLY="$TMP_ROOT/parsed rewritten assembly.S"
REWRITTEN_BEAM="$TMP_ROOT/parsed rewritten candidate.beam"
printf '%s\n' 'original_value.' >"$FROM_TERM"
printf '%s\n' 'parsed_rewrite_value.' >"$TO_TERM"
assert_success 'rewrite-function-term replaces one exact parsed subterm and assemble-checks before writing' "$TOOL" rewrite-function-term --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --entry-label "$VALUE_LABEL" --from-term "$FROM_TERM" --to-term "$TO_TERM" --expected-count 1 --output "$REWRITTEN_ASSEMBLY" --allow-otp-major "$otp_major"
assert_success 'rebuild accepts the parsed exact-term rewrite' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$REWRITTEN_ASSEMBLY" --output "$REWRITTEN_BEAM" --allow-otp-major "$otp_major"
parsed_rewrite_runtime_output=$(erl -noshell -eval "{ok,B}=file:read_file(\"$REWRITTEN_BEAM\"), {module,beam_patch_fixture}=code:load_binary(beam_patch_fixture,\"$REWRITTEN_BEAM\",B), parsed_rewrite_value=beam_patch_fixture:value(), io:format(\"parsed rewrite runtime ok~n\"), halt()." 2>&1)
assert_contains 'parsed rewrite runtime ok' "$parsed_rewrite_runtime_output" 'parsed exact-term rewrite produces a usable BEAM'
NO_MATCH_TERM="$TMP_ROOT/no match.term"
printf '%s\n' 'term_that_is_absent.' >"$NO_MATCH_TERM"
assert_status 70 'rewrite-function-term rejects an unexpected match count' "$TOOL" rewrite-function-term --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --entry-label "$VALUE_LABEL" --from-term "$NO_MATCH_TERM" --to-term "$TO_TERM" --expected-count 1 --output "$TMP_ROOT/no-match-output.S" --allow-otp-major "$otp_major"
if [[ ! -e "$TMP_ROOT/no-match-output.S" ]]; then pass 'failed parsed rewrite leaves no output'; else fail 'failed parsed rewrite leaves no output'; fi
printf '%s\n' '{beam_patch_function,1,{function,value,0,' >"$TMP_ROOT/broken function.term"
assert_status 70 'replace-function rejects an unbalanced isolated term and writes nothing' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/broken function.term" --output "$TMP_ROOT/broken structural output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/broken structural output.S" 'unbalanced function leaves no assembly output'
cp -- "$STRUCTURED_FUNCTION" "$TMP_ROOT/two function terms.term"
printf '%s\n' 'unexpected_second_term.' >>"$TMP_ROOT/two function terms.term"
assert_status 70 'replace-function rejects two top-level terms' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/two function terms.term" --output "$TMP_ROOT/two-term output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/two-term output.S" 'two-term wrapper leaves no assembly output'
assert_status 70 'replace-function rejects changed function MFA' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/wrong-mfa.term" --output "$TMP_ROOT/wrong identity output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/wrong identity output.S" 'wrong-MFA wrapper leaves no assembly output'
assert_status 70 'replace-function rejects changed wrapper entry label' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/wrong-entry.term" --output "$TMP_ROOT/wrong-entry output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/wrong-entry output.S" 'wrong-entry wrapper leaves no assembly output'
assert_status 70 'replace-function rejects a foreign function label' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/foreign-label.term" --output "$TMP_ROOT/foreign-label output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/foreign-label output.S" 'foreign-label wrapper leaves no assembly output'
assert_status 70 'replace-function rejects a stale source assembly digest' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/stale-digest.term" --output "$TMP_ROOT/stale-digest output.S" --allow-otp-major "$otp_major"
assert_absent "$TMP_ROOT/stale-digest output.S" 'stale-digest wrapper leaves no assembly output'
cp -- "$STRUCTURED_ASSEMBLY" "$TMP_ROOT/existing structural output.S"
EXISTING_STRUCTURAL_SHA=$(sha256sum "$TMP_ROOT/existing structural output.S" | awk '{print $1}')
assert_status 73 'replace-function refuses an existing edited assembly output' "$TOOL" replace-function --workspace "$WORKSPACE" --assembly "$WORKSPACE/editable.S" --function "$TMP_ROOT/isolated function edited.term" --output "$TMP_ROOT/existing structural output.S" --allow-otp-major "$otp_major"
[[ $(sha256sum "$TMP_ROOT/existing structural output.S" | awk '{print $1}') == "$EXISTING_STRUCTURAL_SHA" ]] && pass 'existing edited assembly remains byte-identical' || fail 'existing edited assembly remains byte-identical'
PROOF_BASELINE_COPY="$TMP_ROOT/proof baseline editable.S"
cp -- "$WORKSPACE/editable.S" "$PROOF_BASELINE_COPY"
printf '\n' >>"$WORKSPACE/editable.S"
set +e
tampered_proof_output=$("$TOOL" neutral-line-canary --workspace "$WORKSPACE" --entry-label 1 --output "$TMP_ROOT/tampered proof canary.S" --allow-otp-major "$otp_major" 2>&1)
tampered_proof_status=$?
set -e
if [[ $tampered_proof_status -eq 70 && $tampered_proof_output == *roundtrip_proof_mismatch* ]]; then
  pass 'neutral line canary rejects a tampered roundtrip baseline'
else
  printf '%s\n' "$tampered_proof_output" >&2
  fail 'neutral line canary rejects a tampered roundtrip baseline'
fi
mv -- "$PROOF_BASELINE_COPY" "$WORKSPACE/editable.S"
MISMATCH_ASSEMBLY="$TMP_ROOT/cross workspace assembly.S"
erl -noshell -eval "{ok,[{beam_patch_assembly,1,Map}]}=file:consult(\"$WORKSPACE/editable.S\"), Bad={beam_patch_assembly,1,Map#{module => other_workspace_module}}, ok=file:write_file(\"$MISMATCH_ASSEMBLY\",unicode:characters_to_binary(io_lib:format(\"~tp.~n\",[Bad]))), halt()."
set +e
mismatch_output=$("$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$MISMATCH_ASSEMBLY" --output "$TMP_ROOT/cross workspace candidate.beam" --allow-otp-major "$otp_major" 2>&1)
mismatch_status=$?
set -e
if [[ $mismatch_status -eq 70 && $mismatch_output == *edited_assembly_identity_mismatch* ]]; then
  pass 'rebuild rejects an edited assembly from another workspace identity'
else
  printf '%s\n' "$mismatch_output" >&2
  fail 'rebuild rejects an edited assembly from another workspace identity'
fi

CANARY_LABEL=$(erl -noshell -eval "{ok,[{beam_patch_assembly,1,#{functions := Functions}}]}=file:consult(\"$WORKSPACE/editable.S\"), [Label|_]=[Entry || {function,_,_,Entry,Instructions} <- Functions, lists:any(fun({line,_})->true;(_)->false end,Instructions)], io:format(\"~B\",[Label]), halt().")
CANARY_ASSEMBLY="$TMP_ROOT/neutral line canary.S"
set +e
canary_command_output=$("$TOOL" neutral-line-canary --workspace "$WORKSPACE" --entry-label "$CANARY_LABEL" --output "$CANARY_ASSEMBLY" --allow-otp-major "$otp_major" 2>&1)
canary_command_status=$?
set -e
if [[ $canary_command_status -eq 0 ]]; then
  pass 'neutral line canary removes one selected line marker'
  assert_contains 'neutral-line-canary selected' "$canary_command_output" 'neutral line canary prints selected name arity and entry label'
else
  printf '%s\n' "$canary_command_output" >&2
  fail "neutral line canary removes one selected line marker (status $canary_command_status)"
fi
assert_file "$CANARY_ASSEMBLY" 'neutral line canary writes exclusive edited assembly'
assert_status 73 'neutral line canary refuses an existing output' "$TOOL" neutral-line-canary --workspace "$WORKSPACE" --entry-label "$CANARY_LABEL" --output "$CANARY_ASSEMBLY" --allow-otp-major "$otp_major"
set +e
canary_structure_output=$(erl -noshell -eval "{ok,[{beam_patch_assembly,1,Before}]}=file:consult(\"$WORKSPACE/editable.S\"), {ok,[{beam_patch_assembly,1,After}]}=file:consult(\"$CANARY_ASSEMBLY\"), true=maps:remove(functions,Before)=:=maps:remove(functions,After), BeforeFunctions=maps:get(functions,Before), AfterFunctions=maps:get(functions,After), [BeforeFunction]=[F || F={function,_,_,Label,_} <- BeforeFunctions, Label=:=list_to_integer(\"$CANARY_LABEL\")], [AfterFunction]=[F || F={function,_,_,Label,_} <- AfterFunctions, Label=:=list_to_integer(\"$CANARY_LABEL\")], {function,Name,Arity,Label,BeforeInstructions}=BeforeFunction, {function,Name,Arity,Label,AfterInstructions}=AfterFunction, DropFirst=fun Drop([{line,_}|Rest])->Rest; Drop([Head|Rest])->[Head|Drop(Rest)] end, true=AfterInstructions=:=DropFirst(BeforeInstructions), true=[F || F={function,_,_,OtherLabel,_} <- BeforeFunctions, OtherLabel=/=Label]=:=[F || F={function,_,_,OtherLabel,_} <- AfterFunctions, OtherLabel=/=Label], io:format(\"neutral line structure ok~n\"), halt()." 2>&1)
canary_structure_status=$?
set -e
if [[ $canary_structure_status -eq 0 ]]; then
  assert_contains 'neutral line structure ok' "$canary_structure_output" 'neutral line canary changes exactly one line term and nothing else'
else
  printf '%s\n' "$canary_structure_output" >&2
  fail "neutral line canary changes exactly one line term and nothing else (status $canary_structure_status)"
fi
set +e
missing_canary_output=$("$TOOL" neutral-line-canary --workspace "$WORKSPACE" --entry-label 999999999 --output "$TMP_ROOT/missing canary.S" --allow-otp-major "$otp_major" 2>&1)
missing_canary_status=$?
set -e
if [[ $missing_canary_status -eq 70 && $missing_canary_output == *entry_label_not_found* ]]; then
  pass 'neutral line canary reports a missing entry label clearly'
else
  printf '%s\n' "$missing_canary_output" >&2
  fail 'neutral line canary reports a missing entry label clearly'
fi
NO_LINE_ASSEMBLY="$TMP_ROOT/no line marker.S"
erl -noshell -eval "{ok,[{beam_patch_assembly,1,Map}]}=file:consult(\"$WORKSPACE/editable.S\"), Label=list_to_integer(\"$CANARY_LABEL\"), Functions=maps:get(functions,Map), [Target]=[F || F={function,_,_,Entry,_} <- Functions, Entry=:=Label], {function,Name,Arity,Label,Instructions}=Target, NoLine={function,Name,Arity,Label,[I || I <- Instructions, not (is_tuple(I) andalso tuple_size(I)>0 andalso element(1,I)=:=line)]}, Updated=Map#{functions => [case F of {function,_,_,Label,_}->NoLine; _->F end || F <- Functions]}, ok=file:write_file(\"$NO_LINE_ASSEMBLY\",unicode:characters_to_binary(io_lib:format(\"~tp.~n\",[{beam_patch_assembly,1,Updated}]))),halt()."
set +e
no_line_canary_output=$(escript "$HELPER_PREFLIGHT" neutral_line_canary "$NO_LINE_ASSEMBLY" "$CANARY_LABEL" "$TMP_ROOT/no line output.S" 2>&1)
no_line_canary_status=$?
set -e
if [[ $no_line_canary_status -eq 70 && $no_line_canary_output == *no_line_marker* ]]; then
  pass 'neutral line canary reports a missing line marker clearly'
else
  printf '%s\n' "$no_line_canary_output" >&2
  fail 'neutral line canary reports a missing line marker clearly'
fi
DUPLICATE_ASSEMBLY="$TMP_ROOT/duplicate entry label.S"
erl -noshell -eval "{ok,[{beam_patch_assembly,1,Map}]}=file:consult(\"$WORKSPACE/editable.S\"), Label=list_to_integer(\"$CANARY_LABEL\"), Functions=maps:get(functions,Map), [Target]=[F || F={function,_,_,Entry,_} <- Functions, Entry=:=Label], Updated=Map#{functions => Functions ++ [Target]}, ok=file:write_file(\"$DUPLICATE_ASSEMBLY\",unicode:characters_to_binary(io_lib:format(\"~tp.~n\",[{beam_patch_assembly,1,Updated}]))),halt()."
set +e
duplicate_canary_output=$(escript "$HELPER_PREFLIGHT" neutral_line_canary "$DUPLICATE_ASSEMBLY" "$CANARY_LABEL" "$TMP_ROOT/duplicate output.S" 2>&1)
duplicate_canary_status=$?
set -e
if [[ $duplicate_canary_status -eq 70 && $duplicate_canary_output == *duplicate_entry_label* ]]; then
  pass 'neutral line canary reports a duplicate entry label clearly'
else
  printf '%s\n' "$duplicate_canary_output" >&2
  fail 'neutral line canary reports a duplicate entry label clearly'
fi
CANARY_BEAM="$TMP_ROOT/neutral line canary.beam"
assert_success 'rebuild accepts neutral line metadata canary with matching proof' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$CANARY_ASSEMBLY" --output "$CANARY_BEAM" --allow-otp-major "$otp_major"
assert_success 'verify accepts neutral line metadata canary' "$TOOL" verify --original "$INPUT" --candidate "$CANARY_BEAM" --allow-otp-major "$otp_major"
canary_runtime_output=$(erl -noshell -eval "{ok,Binary}=file:read_file(\"$CANARY_BEAM\"), {module,beam_patch_fixture}=code:load_binary(beam_patch_fixture,\"$CANARY_BEAM\",Binary), original_value=beam_patch_fixture:value(), true=is_pid(beam_patch_fixture:self_value()), io:format(\"neutral line runtime ok~n\"), halt()." 2>&1)
assert_contains 'neutral line runtime ok' "$canary_runtime_output" 'neutral line canary rebuild loads with unchanged logic'

assert_status 73 'roundtrip refuses an existing candidate output' "$TOOL" roundtrip --input "$INPUT" --workspace "$WORKSPACE" --allow-otp-major "$otp_major"

EDITED="$TMP_ROOT/edited fixture.S"
sed 's/original_value/patched_value/g' "$WORKSPACE/editable.S" >"$EDITED"
PATCHED="$TMP_ROOT/patched fixture.beam"
assert_success 'rebuild accepts a benign literal edit with matching proof' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$EDITED" --output "$PATCHED" --allow-otp-major "$otp_major"
assert_success 'verify accepts the benign edited candidate' "$TOOL" verify --original "$INPUT" --candidate "$PATCHED" --allow-otp-major "$otp_major"
meta_output=$(erl -noshell -eval "{ok,_,Chunks}=beam_lib:all_chunks(\"$PATCHED\"), true=is_binary(proplists:get_value(\"Meta\",Chunks)), io:format(\"meta preserved~n\"), halt()." 2>&1)
assert_contains 'meta preserved' "$meta_output" 'rebuild preserves Meta extra chunk'
assert_status 73 'rebuild refuses an existing candidate output' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$EDITED" --output "$PATCHED" --allow-otp-major "$otp_major"
set +e
occupied_output=$("$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$EDITED" --output "$PATCHED" --allow-otp-major "$otp_major" 2>&1)
occupied_status=$?
set -e
if [[ $occupied_status -eq 73 && $occupied_output == *'suggested_output='* ]]; then
  pass 'occupied output refusal prints an exact safe versioned suggestion'
else
  printf '%s\n' "$occupied_output" >&2
  fail "occupied output refusal prints an exact safe versioned suggestion (status $occupied_status)"
fi
assert_success 'auto-version-output selects and writes a non-existing candidate path' "$TOOL" rebuild --workspace "$WORKSPACE" --assembly "$EDITED" --output "$PATCHED" --auto-version-output --allow-otp-major "$otp_major"
assert_file "$TMP_ROOT/patched fixture.v1.beam" 'auto-version-output preserves the extension and adds a numeric version'

set +e
runtime_output=$(erl -noshell -pa "$TMP_ROOT" -eval "{ok,FixtureBinary}=file:read_file(\"$PATCHED\"), {module,beam_patch_fixture}=code:load_binary(beam_patch_fixture,\"$PATCHED\",FixtureBinary), patched_value=beam_patch_fixture:value(), {ok,probe}=beam_patch_fixture:echo(probe), 2=beam_patch_fixture:static_apply(), {ok,probe}=beam_patch_fixture:known_fun(), 0=beam_patch_fixture:dynamic_apply(erlang,length), 0=beam_patch_fixture:partial_apply(length), 1=beam_patch_fixture:branch_apply(true), one=beam_patch_fixture:branch_apply(false), {ok,probe}=beam_patch_fixture:dynamic_fun_call(fun beam_patch_fixture:echo/1), {ok,probe}=beam_patch_fixture:fully_dynamic_apply(fun beam_patch_fixture:echo/1,[probe]), {ok,0}=beam_patch_fixture:beam_apply(erlang,length,[]), 0=beam_patch_fixture:beam_apply_last(erlang,length,[]), {local_call,{local_target,probe}}=beam_patch_fixture:local_call(probe), {local_target,probe}=beam_patch_fixture:local_tail_call(probe), Self=beam_patch_fixture:self_value(), true=is_pid(Self), io:format(\"fixture runtime ok~n\"), halt()." 2>&1)
runtime_status=$?
set -e
if [[ $runtime_status -eq 0 ]]; then
  assert_contains 'fixture runtime ok' "$runtime_output" 'only the benign candidate loads and executes in a disposable runtime'
else
  printf '%s\n' "$runtime_output" >&2
  fail "only the benign candidate loads and executes in a disposable runtime (loader status $runtime_status)"
fi

if (( failures > 0 )); then
  printf '%d test(s) failed\n' "$failures" >&2
  exit 1
fi
printf 'all tests passed\n'
