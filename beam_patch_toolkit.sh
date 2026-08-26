#!/usr/bin/env bash
# Safe, structural BEAM extraction and reconstruction for authorized analysis.
set -euo pipefail
umask 077

PROGRAM=${0##*/}
EX_USAGE=64
EX_UNSAFE=65
EX_NOINPUT=66
EX_SOFTWARE=70
EX_EXISTS=73

usage() {
  cat <<'HELP'
Erlang BEAM Toolkit for Linux

Usage:
  beam_patch_toolkit.sh help
  beam_patch_toolkit.sh unpack --input INPUT --output OUTPUT [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh decrypt-aes --input INPUT --output OUTPUT --key1-file FILE --key2-file FILE [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh doctor --input BEAM [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh workspace-status --workspace DIR [--input BEAM]
  beam_patch_toolkit.sh extract --input BEAM --workspace DIR [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh roundtrip --input BEAM --workspace DIR [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh rebuild --workspace WORKSPACE --assembly EDITED.S --output CANDIDATE.beam [--auto-version-output] [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh verify --original ORIGINAL.beam --candidate CANDIDATE.beam [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh export-function --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --output FUNCTION.term [--auto-version-output] [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh replace-function --workspace WORKSPACE --assembly ASSEMBLY.S --function FUNCTION.term --output EDITED.S [--auto-version-output] [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh rewrite-function-term --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --from-term FROM.term --to-term TO.term --expected-count N --output EDITED.S [--auto-version-output] [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh validate-assembly --workspace WORKSPACE --assembly ASSEMBLY.S [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh neutral-line-canary --workspace WORKSPACE --entry-label N --output EDITED.S [--auto-version-output] [--runtime-bin DIR] [--allow-otp-major MAJOR]
  beam_patch_toolkit.sh flow --mode MODE --output FLOW_OR_TRACE_DIR [--scope SCOPE] [--beam BEAM]... [--beam-dir DIR]... [--graph FLOW_DIR] [--scenario SCENARIO.term] [--node NAME@HOST] [--cookie-file FILE] [--process SELECTOR]... [--functions SELECTOR]... [--events SELECTOR]... [--duration SECONDS] [--max-events N] [--max-bytes N] [--trace-backend BACKEND] [--isolation CHOICE] [--unbounded-live-trace --acknowledge-live-risk] [--allow-legacy-live-trace] [--runtime-bin DIR]
  beam_patch_toolkit.sh flow-query --graph FLOW_DIR --from MODULE:FUNCTION/ARITY [--direction DIRECTION] [--max-depth N] [--format term|json] [--runtime-bin DIR]
  beam_patch_toolkit.sh trace-scenario-check --scenario SCENARIO.term [--runtime-bin DIR]
  beam_patch_toolkit.sh trace-raw-check --input events.raw.etf [--max-bytes N] [--runtime-bin DIR]

Commands:
  unpack     Expand an outer-gzip BEAM to an ordinary FOR1/BEAM file.
  decrypt-aes
             Decrypt the supported Dbgi/Abst AES-256-CTR envelope using two
             owner-only key files, reconstruct Code/LitT, and validate fully.
  doctor     Check Bash/Erlang dependencies, OTP major, and BEAM readability.
  workspace-status
             Diagnose absent, incomplete, extracted, or roundtrip-proven
             workspaces without requiring Erlang. Lists every expected artifact.
  extract    Transactionally create, or safely reuse, a complete matching
             workspace with editable assembly, original, chunks, and metadata.
  roundtrip  Rebuild unchanged workspace/editable.S and verify semantic identity.
  rebuild    Assemble an edited assembly only with its verified workspace proof.
  verify     Compare two BEAM files structurally without loading either module.
  export-function
             Write one independently consultable, identity-bound function term.
  replace-function
             Structurally splice one parsed function term and assemble-check it.
  rewrite-function-term
             Recursively replace one exact parsed Erlang subterm inside one
             selected function, require an exact match count, and assemble-check.
  validate-assembly
             Parse, identity-check, and assemble an edited term without output.
  neutral-line-canary
             Remove one source-line metadata term from verified workspace/editable.S.
  flow       Build a complete static graph or add isolated/live runtime evidence.
             Modes: static, isolated-runtime, live-runtime. Static scopes are
             single, supplied, tree; supplied is the default and no records are
             filtered from the authoritative output.
  flow-query Read a committed graph and produce a focused callers/callees view
             without changing or filtering its authoritative dataset.
  trace-scenario-check
             Parse and validate one declarative beam_flow_scenario_v1 term.
  trace-raw-check
             Validate every 64-bit-length-prefixed ETF frame without decoding it.
  help       Print this complete help.

Flow selection and tracing:
  Static scopes: single, supplied, tree. The authoritative graph always retains
    every discovered function, instruction, dependency, call, unknown, and
    unsupported record; scope chooses the supplied module universe, not a
    display filter.
  Isolation choices: auto, process, namespace. auto currently selects process;
    process is a disposable peer node, not a security sandbox. namespace is a
    reserved explicit capability request and exits 66 when unavailable.
  Backends: auto, session, dbg, legacy. auto selects session, then dbg; it never selects legacy.
    session uses the OTP trace-session API. dbg uses an isolated dbg session and
    destroys its owned underlying trace session. legacy snapshots and restores
    the exact selected global trace state and requires both
    --allow-legacy-live-trace and --acknowledge-live-risk.
  Process selectors: all, existing, new, registered:NAME, pid:<PID>.
    At least one repeatable --process is required for live tracing.
  Function selectors: all-supplied, all-loaded, MODULE:FUNCTION/ARITY
    where FUNCTION or ARITY may be _ for a module present in the static graph.
    With no --functions, every function from the supplied static graph is used.
  Event selectors: all, call, return, exception, process, send, receive,
    garbage_collection, scheduler. With no --events, call/process/send/receive
    families are captured. Selectors control instrumentation; captured records
    are never silently filtered from authoritative trace output.
  Default live bounds: duration=30 seconds, max-events=100000,
    max-bytes=1073741824. The first reached bound stops capture and is recorded.
    --unbounded-live-trace disables all three quotas only when accompanied by
    --acknowledge-live-risk; foreground SIGINT/SIGTERM still requests cleanup.
  A cleanup failure commits partial evidence and exits 70. Never treat a
    missing .beam-flow-trace marker or a failed cleanup field as a complete run.

Artifact authority and queries:
  Authoritative: flow-ir.term for static analysis and events.raw.etf
    for runtime capture. TERM family files, normalized JSON/JSONL, DOT, SVG,
    GraphML, and offline HTML are complete or reconciled derived views.
  flow-query origins use MODULE:FUNCTION/ARITY. Directions: callers, callees, both. Formats: term, json.
    --max-depth is a nonnegative view bound; results retain authoritative and
    focused counts so a query cannot be mistaken for filtered source data.

Safety contract:
  * OTP 27, 28, and 29 are supported. --runtime-bin DIR selects matching
    erl/escript executables; the exact paths and OTP/ERTS are provenance-bound.
    --allow-otp-major MAJOR remains an explicit exact-version assertion.
  * Inputs, editable assembly, extras, and candidates must be readable regular
    non-symlinks. Paths containing spaces are supported.
  * AES keys are read only from non-symlink, owner-only files containing exactly
    64 hexadecimal characters. Keys are never accepted on the command line,
    recorded in a workspace, or printed. Decryption writes only after envelope,
    container, module, export-label, function-count, and disassembly checks.
  * on_load metadata and its decoded function are included, not filtered.
    Input BEAMs are never loaded or executed, so their on_load hook is not
    invoked; the toolkit never calls code:load_binary/3. Only a separately
    chosen disposable test runtime may load a benign candidate.
  * Existing inputs and candidate outputs are never overwritten. An existing
    workspace must be a non-symlink directory marked with .beam-patch-workspace.
    --auto-version-output selects a non-existing .vN path instead of overwriting.
    Failed extraction is transactional and leaves no partial target workspace.
  * The function wrapper is bound to source SHA-256, module, MFA, entry,
    and the complete owned-label set. Replacement accepts exactly one parsed
    wrapper and assembles the complete module before committing a new output.
  * Rebuild preserves valid non-regenerated four-byte chunks (including Meta).
    It regenerates Atom AtU8 Code StrT ImpT ExpT LocT FunT LitT Attr CInf Dbgi
    Abst Line Type Docs DbgB Recs; byte equality is neither expected nor needed.
  * Bounded live tracing is the default. Quota-free tracing requires the exact
    pair --unbounded-live-trace --acknowledge-live-risk. Legacy tracing also
    requires --allow-legacy-live-trace and is never selected automatically.
  * Static flow never loads inspected code. Isolated-runtime may invoke on_load
    because it loads requested modules in a disposable node. Live-runtime never
    replaces code, loads candidate modules, or restarts an application.

Workflow:
  beam_patch_toolkit.sh doctor --input "/path with spaces/module.beam"
  beam_patch_toolkit.sh extract --input "/path with spaces/module.beam" --workspace "/safe/workspace"
  beam_patch_toolkit.sh roundtrip --input "/path with spaces/module.beam" --workspace "/safe/workspace"
  # Edit only after unchanged roundtrip writes .roundtrip-verified.term.
  # Prefer function-level edits; do not repair editable.S by counting braces.
  beam_patch_toolkit.sh export-function --workspace "/safe/workspace" --assembly "/safe/workspace/editable.S" --entry-label 42 --output "/safe/function.term"
  # Edit only /safe/function.term, then splice and validate it structurally.
  beam_patch_toolkit.sh replace-function --workspace "/safe/workspace" --assembly "/safe/workspace/editable.S" --function "/safe/function.term" --output "/safe/edited.S"
  # For exact structural substitutions, FROM.term and TO.term each contain one
  # consultable Erlang term ending in a period. No text or brace editing occurs.
  beam_patch_toolkit.sh rewrite-function-term --workspace "/safe/workspace" --assembly "/safe/workspace/editable.S" --entry-label 42 --from-term "/safe/from.term" --to-term "/safe/to.term" --expected-count 1 --output "/safe/edited.S"
  beam_patch_toolkit.sh validate-assembly --workspace "/safe/workspace" --assembly "/safe/edited.S"
  # This canary changes diagnostics/stacktrace line metadata only, not logic.
  beam_patch_toolkit.sh neutral-line-canary --workspace "/safe/workspace" --entry-label 42 --output "/safe/canary.S"
  beam_patch_toolkit.sh rebuild --workspace "/safe/workspace" --assembly "/safe/canary.S" --output "/safe/candidate.beam"
  beam_patch_toolkit.sh verify --original "/path with spaces/module.beam" --candidate "/safe/candidate.beam"

Workspace contents:
  .beam-patch-workspace  marker and recorded source identity
  original.beam          read-only original copy
  original.sha256        SHA-256 of original.beam
  manifest.term          module/chunk/count metadata
  raw_chunks/            raw chunk payloads, indexed without trusting chunk text
  disassembly.term       original beam_disasm:file/1 term
  editable.S             consultable {beam_patch_assembly,1,Map} term
  extra_chunks.term      preserved non-regenerated chunks
  .roundtrip-verified.term  versioned hashes and OTP/ERTS provenance proof
  functions.term         complete decoded function inventory (no filters)
  dependencies.term      complete per-function dependency inventory (no filters)
  dynamic_calls.term     every dynamic call: exact, partial, or unresolved

Flow graph contents:
  flow-ir.term            authoritative complete static graph and counts
  functions.term          every decoded function with stable ID and location
  dependencies.term       every per-function dependency and call certainty
  dynamic-calls.term      every exact, possible, partial, unresolved callsite
  blocks/instructions/CFG family terms plus JSON, DOT, SVG, GraphML, flow.html

Runtime trace contents:
  events.raw.etf          authoritative 64-bit-length-framed ETF events
  events.term / events.normalized.jsonl / timeline.json
  runtime-overlay.term    additive static-to-runtime correlation
  runtime-processes.term / runtime-edges.term / runtime-unmatched.term
  runtime.dot / optional runtime.svg / offline flow.html
  trace-manifest.term and trace-completeness.term with bounds and cleanup proof

Exit status: 64 usage, 65 unsafe path, 66 unreadable/missing input,
70 processing, validation, or partial-trace failure, 73 attempted
overwrite/reuse of an unmarked target.

Troubleshooting:
  * Run workspace-status before reusing a workspace. Never repair a partial
    editable.S by balancing braces or appending delimiters.
  * Exit 73 preserves the existing output and prints suggested_output=PATH.
    Re-run with that path or pass --auto-version-output.
  * Direct probes must terminate explicitly, for example:
      erl -noshell -eval 'io:format("~tp~n",[beam_lib:chunks("m.beam",[abstract_code])]),halt().'
    A stripped BEAM may legitimately report no_abstract_code.

The canary changes diagnostics/stacktrace line metadata only; it is not a
license, activation, entitlement, validation, presence-control, or any other
bypass. There is deliberately no deployment command.
HELP
}

die() { local code=$1; shift; printf '%s: %s\n' "$PROGRAM" "$*" >&2; exit "$code"; }
need_command() { command -v "$1" >/dev/null 2>&1 || die "$EX_NOINPUT" "required command not found: $1"; }

canonical_existing_file() {
  local path=${1-} dir base
  [[ -n $path ]] || die "$EX_NOINPUT" "input path is empty"
  [[ ! -L $path ]] || die "$EX_UNSAFE" "input must not be a symlink: $path"
  [[ -f $path && -r $path ]] || die "$EX_NOINPUT" "input must be a readable regular file: $path"
  dir=$(cd -P -- "$(dirname -- "$path")" && pwd -P)
  base=$(basename -- "$path")
  printf '%s/%s\n' "$dir" "$base"
}

canonical_secret_file() {
  local path mode owner current canonical
  canonical=$(canonical_existing_file "$1") || return $?
  need_command stat
  mode=$(stat -c '%a' -- "$canonical") || die "$EX_UNSAFE" "cannot inspect key-file permissions"
  owner=$(stat -c '%u' -- "$canonical") || die "$EX_UNSAFE" "cannot inspect key-file owner"
  current=$(id -u)
  [[ $mode =~ ^[0-7]{3,4}$ ]] || die "$EX_UNSAFE" "unrecognized key-file permissions"
  (( (8#$mode & 8#077) == 0 )) || die "$EX_UNSAFE" "key file must not be accessible by group or others: $canonical"
  [[ $owner == "$current" ]] || die "$EX_UNSAFE" "key file must be owned by the current user: $canonical"
  printf '%s\n' "$canonical"
}

canonical_new_path() {
  local path=${1-} dir base
  [[ -n $path && $path != / ]] || die "$EX_UNSAFE" "unsafe empty or root target"
  base=$(basename -- "$path")
  [[ $base != . && $base != / && -n $base ]] || die "$EX_UNSAFE" "unsafe target basename"
  dir=$(dirname -- "$path")
  [[ -d $dir && ! -L $dir ]] || die "$EX_UNSAFE" "target parent must be an existing non-symlink directory: $dir"
  dir=$(cd -P -- "$dir" && pwd -P)
  printf '%s/%s\n' "$dir" "$base"
}

canonical_existing_directory() {
  local path=${1-}
  [[ -n $path ]] || die "$EX_NOINPUT" "directory path is empty"
  [[ ! -L $path && -d $path && -x $path ]] || die "$EX_NOINPUT" "directory must be an accessible non-symlink: $path"
  (cd -P -- "$path" && pwd -P)
}

workspace_state() {
  local workspace=$1 name
  WORKSPACE_MISSING=()
  WORKSPACE_PROOF_MISSING=()
  for name in original.beam original.sha256 manifest.term disassembly.term editable.S extra_chunks.term functions.term dependencies.term dynamic_calls.term; do
    [[ -f $workspace/$name && ! -L $workspace/$name ]] || WORKSPACE_MISSING+=("$name")
  done
  [[ -d $workspace/raw_chunks && ! -L $workspace/raw_chunks ]] || WORKSPACE_MISSING+=("raw_chunks/")
  for name in roundtrip.beam .roundtrip-verified.term; do
    [[ -f $workspace/$name && ! -L $workspace/$name ]] || WORKSPACE_PROOF_MISSING+=("$name")
  done
  if ((${#WORKSPACE_MISSING[@]})); then
    WORKSPACE_STATE=incomplete
  elif ((${#WORKSPACE_PROOF_MISSING[@]})); then
    WORKSPACE_STATE=extracted
  else
    WORKSPACE_STATE=proven
  fi
}

join_by_comma() {
  local result= item
  for item in "$@"; do
    [[ -z $result ]] || result+=,
    result+=$item
  done
  printf '%s\n' "${result:-none}"
}

versioned_path() {
  local path=$1 dir name stem extension candidate n
  dir=${path%/*}
  name=${path##*/}
  if [[ $name == *.* && $name != .* ]]; then
    stem=${name%.*}
    extension=.${name##*.}
  else
    stem=$name
    extension=
  fi
  n=1
  while ((n <= 999999)); do
    candidate=$dir/$stem.v$n$extension
    if [[ ! -e $candidate && ! -L $candidate ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    n=$((n + 1))
  done
  die "$EX_EXISTS" "unable to select a non-existing versioned path for: $path"
}

select_output_path() {
  local requested=$1 kind=$2 suggested
  SELECTED_OUTPUT=$(canonical_new_path "$requested")
  if [[ -e $SELECTED_OUTPUT || -L $SELECTED_OUTPUT ]]; then
    suggested=$(versioned_path "$SELECTED_OUTPUT")
    if [[ ${AUTO_VERSION_OUTPUT:-0} == 1 ]]; then
      SELECTED_OUTPUT=$suggested
      printf '%s: selected_output=%s\n' "$PROGRAM" "$SELECTED_OUTPUT" >&2
    else
      die "$EX_EXISTS" "refusing existing $kind output: $SELECTED_OUTPUT; suggested_output=$suggested"
    fi
  fi
}

TRANSACTION_TARGET=
TRANSACTION_DIR=

begin_directory_transaction() {
  local requested=$1 parent base
  TRANSACTION_TARGET=$(canonical_new_path "$requested")
  [[ ! -e $TRANSACTION_TARGET && ! -L $TRANSACTION_TARGET ]] ||
    die "$EX_EXISTS" "refusing existing graph or trace output: $TRANSACTION_TARGET; suggested_output=$(versioned_path "$TRANSACTION_TARGET")"
  parent=${TRANSACTION_TARGET%/*}
  base=${TRANSACTION_TARGET##*/}
  TRANSACTION_DIR=$(mktemp -d "$parent/.${base}.tmp.XXXXXX")
  chmod 700 -- "$TRANSACTION_DIR"
}

commit_directory_transaction() {
  local marker=$1
  [[ -n $TRANSACTION_DIR && -d $TRANSACTION_DIR && ! -L $TRANSACTION_DIR ]] ||
    die "$EX_UNSAFE" "owned directory transaction is unavailable"
  : >"$TRANSACTION_DIR/$marker"
  mv -Tn -- "$TRANSACTION_DIR" "$TRANSACTION_TARGET"
  [[ ! -e $TRANSACTION_DIR && ! -L $TRANSACTION_DIR ]] ||
    die "$EX_EXISTS" "graph or trace target appeared during transactional commit: $TRANSACTION_TARGET"
  TRANSACTION_DIR=
}

cleanup_directory_transaction() {
  if [[ -n ${TRANSACTION_DIR:-} && -d $TRANSACTION_DIR && ! -L $TRANSACTION_DIR ]]; then
    rm -rf -- "$TRANSACTION_DIR"
  fi
}

report_output() {
  printf '%s: output=%s\n' "$PROGRAM" "$1" >&2
}

prepare_extract_workspace() {
  local requested=$1 input=$2 suggested
  PREPARED_WORKSPACE=$(canonical_new_path "$requested")
  PREPARED_WORKSPACE_REUSE=0
  [[ $PREPARED_WORKSPACE != "$input" ]] || die "$EX_UNSAFE" "workspace aliases input"
  if [[ -e $PREPARED_WORKSPACE || -L $PREPARED_WORKSPACE ]]; then
    [[ -d $PREPARED_WORKSPACE && ! -L $PREPARED_WORKSPACE &&
       -f $PREPARED_WORKSPACE/.beam-patch-workspace &&
       ! -L $PREPARED_WORKSPACE/.beam-patch-workspace ]] ||
      die "$EX_EXISTS" "existing workspace is not safely marked: $PREPARED_WORKSPACE"
    workspace_state "$PREPARED_WORKSPACE"
    if [[ $WORKSPACE_STATE == incomplete ]]; then
      suggested=$(versioned_path "$PREPARED_WORKSPACE")
      die "$EX_EXISTS" "incomplete workspace: $PREPARED_WORKSPACE; missing=$(join_by_comma "${WORKSPACE_MISSING[@]}"); use a new --workspace path; suggested_workspace=$suggested"
    fi
    require_workspace_input_match "$input" "$PREPARED_WORKSPACE"
    PREPARED_WORKSPACE_REUSE=1
  fi
}

workspace_status_command() {
  local requested=$1 input=${2-} workspace item input_match=not-requested
  [[ -n $requested && ! -L $requested && -d $requested ]] ||
    die "$EX_NOINPUT" "workspace must be an existing non-symlink directory: $requested"
  workspace=$(cd -P -- "$requested" && pwd -P)
  [[ -f $workspace/.beam-patch-workspace && ! -L $workspace/.beam-patch-workspace ]] ||
    die "$EX_UNSAFE" "workspace is not safely marked: $workspace"
  workspace_state "$workspace"
  if [[ -n $input ]]; then
    input=$(canonical_existing_file "$input")
    if cmp -s -- "$input" "$workspace/original.beam"; then input_match=yes; else input_match=no; fi
  fi
  printf 'workspace=%s\nstate=%s\ninput_match=%s\nmissing=%s\nproof_missing=%s\n' \
    "$workspace" "$WORKSPACE_STATE" "$input_match" \
    "$(join_by_comma "${WORKSPACE_MISSING[@]}")" \
    "$(join_by_comma "${WORKSPACE_PROOF_MISSING[@]}")"
  for item in .beam-patch-workspace original.beam original.sha256 manifest.term disassembly.term editable.S extra_chunks.term functions.term dependencies.term dynamic_calls.term raw_chunks/ roundtrip.beam .roundtrip-verified.term; do
    if [[ -e $workspace/${item%/} || -L $workspace/${item%/} ]]; then
      printf 'artifact=%s status=present\n' "$item"
    else
      printf 'artifact=%s status=missing\n' "$item"
    fi
  done
}

require_extracted_workspace() {
  local requested=${1-} workspace name
  [[ -n $requested && ! -L $requested && -d $requested ]] || die "$EX_NOINPUT" "workspace must be an existing non-symlink directory: $requested"
  workspace=$(cd -P -- "$requested" && pwd -P)
  [[ -f $workspace/.beam-patch-workspace && ! -L $workspace/.beam-patch-workspace ]] || die "$EX_NOINPUT" "workspace is not safely marked: $workspace"
  for name in original.beam editable.S extra_chunks.term manifest.term; do
    canonical_existing_file "$workspace/$name" >/dev/null
  done
  printf '%s\n' "$workspace"
}

require_proven_workspace() {
  local workspace name
  workspace=$(require_extracted_workspace "$1")
  for name in roundtrip.beam .roundtrip-verified.term; do
    canonical_existing_file "$workspace/$name" >/dev/null
  done
  printf '%s\n' "$workspace"
}

require_workspace_input_match() {
  local input=$1 workspace=$2
  cmp -s -- "$input" "$workspace/original.beam" ||
    die "$EX_UNSAFE" "workspace original does not match --input byte-for-byte: $workspace"
}

otp_major() {
  "$ERL_COMMAND" -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().' 2>/dev/null
}

configure_runtime() {
  local runtime_bin erl_path erlc_path escript_path
  if [[ -n ${RUNTIME_BIN:-} ]]; then
    runtime_bin=$(canonical_existing_directory "$RUNTIME_BIN")
    erl_path=$(canonical_existing_file "$runtime_bin/erl")
    erlc_path=$(canonical_existing_file "$runtime_bin/erlc")
    escript_path=$(canonical_existing_file "$runtime_bin/escript")
    [[ -x $erl_path ]] || die "$EX_NOINPUT" "selected erl is not executable: $erl_path"
    [[ -x $erlc_path ]] || die "$EX_NOINPUT" "selected erlc is not executable: $erlc_path"
    [[ -x $escript_path ]] || die "$EX_NOINPUT" "selected escript is not executable: $escript_path"
    ERL_COMMAND=$erl_path
    ERLC_COMMAND=$erlc_path
    ESCRIPT_COMMAND=$escript_path
  else
    need_command erl
    need_command erlc
    need_command escript
    ERL_COMMAND=$(command -v erl)
    ERLC_COMMAND=$(command -v erlc)
    ESCRIPT_COMMAND=$(command -v escript)
  fi
}

check_otp() {
  local actual allowed=${1-}
  actual=$(otp_major)
  if [[ -z $allowed ]]; then
    case $actual in
      27|28|29) ;;
      *) die "$EX_NOINPUT" "supported OTP majors are 27, 28, and 29 (found OTP $actual)" ;;
    esac
  else
    [[ $allowed =~ ^[0-9]+$ ]] || die "$EX_USAGE" "--allow-otp-major must be a numeric OTP major"
    [[ $actual == "$allowed" ]] || die "$EX_NOINPUT" "OTP override requires $allowed but found OTP $actual"
    printf '%s: explicit OTP major override accepted: %s\n' "$PROGRAM" "$actual" >&2
  fi
}

helper_source() {
  cat <<'ESCRIPT'
#!/usr/bin/env escript
%%! -noshell
-mode(compile).
-include_lib("kernel/include/file.hrl").

main(Args) ->
    try dispatch(Args) of
        ok -> ok;
        {error, Reason} -> fail(Reason)
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "beam helper error: ~tp:~tp~n~tp~n", [Class, Reason, Stack]),
            halt(70)
    end.

dispatch(["doctor", Beam]) -> doctor(Beam);
dispatch(["unpack", Input, Output]) -> unpack_outer(Input, Output);
dispatch(["decrypt_aes", Input, Output, Key1Path, Key2Path]) -> decrypt_aes(Input, Output, Key1Path, Key2Path);
dispatch(["extract", Beam, Workspace]) -> extract(Beam, Workspace);
dispatch(["roundtrip", Assembly, Extras, Output, Original]) -> roundtrip(Assembly, Extras, Output, Original);
dispatch(["rebuild", Assembly, Extras, Output]) -> rebuild(Assembly, Extras, Output);
dispatch(["verify", Original, Candidate]) -> verify(Original, Candidate);
dispatch(["export_function", Assembly, EntryLabel, Output]) -> export_function(Assembly, EntryLabel, Output);
dispatch(["replace_function", Assembly, Function, Extras, Output]) -> replace_function(Assembly, Function, Extras, Output);
dispatch(["rewrite_function_term", Assembly, EntryLabel, From, To, Expected, Extras, Output]) ->
    rewrite_function_term(Assembly, EntryLabel, From, To, Expected, Extras, Output);
dispatch(["validate_assembly", Assembly, Extras]) -> validate_assembly(Assembly, Extras);
dispatch(["neutral_line_canary", Assembly, EntryLabel, Output]) -> neutral_line_canary(Assembly, EntryLabel, Output);
dispatch(["validate_roundtrip_proof", Workspace]) -> validate_roundtrip_proof(Workspace);
dispatch(["validate_edited_assembly", Baseline, Edited]) -> validate_edited_assembly(Baseline, Edited);
dispatch(["forms_fixture", Output]) -> forms_fixture(Output);
dispatch(["normalization_fixture", Output]) -> normalization_fixture(Output);
dispatch(["normalization_missing_target"]) -> normalization_missing_target();
dispatch(["normalization_missing_fun_label"]) -> normalization_missing_fun_label();
dispatch(["normalization_invalid_fun_arity"]) -> normalization_invalid_fun_arity();
dispatch(["flow_static", Output, Scope, BeamCount, DirCount | Paths]) ->
    flow_static(Output, Scope, BeamCount, DirCount, Paths);
dispatch(["flow_query", GraphDir, Origin, Direction, MaxDepth, Format]) ->
    flow_query(GraphDir, Origin, Direction, MaxDepth, Format);
dispatch(["scenario_check", ScenarioPath]) -> scenario_check(ScenarioPath);
dispatch(["trace_raw_check", Input, MaximumFrameBytes]) ->
    trace_raw_check(Input, MaximumFrameBytes);
dispatch(["flow_isolated", Output, GraphDir, ScenarioPath,
          IsolationRequested, IsolationEffective, AgentBeam]) ->
    flow_isolated(Output, GraphDir, ScenarioPath,
                  IsolationRequested, IsolationEffective, AgentBeam);
dispatch(["flow_live", Output, GraphDir, NodeText, CookiePath, BackendText,
          DurationText, MaxEventsText, MaxBytesText, AgentBeam,
          ControlPath, LegacyAuthorizedText, ProcessCountText,
          FunctionCountText, EventCountText | Selectors]) ->
    flow_live(Output, GraphDir, NodeText, CookiePath, BackendText,
              DurationText, MaxEventsText, MaxBytesText, AgentBeam,
              ControlPath, LegacyAuthorizedText, ProcessCountText,
              FunctionCountText, EventCountText, Selectors);
dispatch(_) -> {error, bad_helper_arguments}.

fail(Reason) -> io:format(standard_error, "beam helper error: ~tp~n", [Reason]), halt(70).

unpack_outer(Input, Output) ->
    ensure_modules(),
    Raw = read_binary(Input),
    {FormatFacts, Binary} = container_facts(Raw),
    ensure_runtime_support(FormatFacts),
    gzip = maps:get(outer_container, FormatFacts),
    true = byte_size(Binary) =< 536870912,
    {ok, Module, _Chunks} = beam_lib:all_chunks(Binary),
    {beam_file, Module, _Exports, _Attrs, _Compile, _Functions} = beam_disasm:file(Binary),
    write_binary_exclusive(Output, Binary),
    io:format("~tp.~n", [FormatFacts#{module => Module,
                                      input_bytes => byte_size(Raw),
                                      output_bytes => byte_size(Binary)}]),
    ok.

decrypt_aes(Input, Output, Key1Path, Key2Path) ->
    ensure_modules(),
    Key1 = read_aes_key(Key1Path),
    Key2 = read_aes_key(Key2Path),
    {FormatFacts, Binary} = container_facts(read_binary(Input)),
    ensure_runtime_support(FormatFacts),
    for1 = maps:get(outer_container, FormatFacts),
    Chunks = parse_iff(Binary),
    {ok, Module, _} = beam_lib:all_chunks(Binary),
    ModuleBin = atom_to_binary(Module),
    {Selector1, PlainCodeBody, Digest1} = decrypt_envelope(<<"Dbgi">>, raw_chunk(<<"Dbgi">>, Chunks), ModuleBin, Key1, Key2),
    {Selector2, PlainLitT, Digest2} = decrypt_envelope(<<"Abst">>, raw_chunk(<<"Abst">>, Chunks), ModuleBin, Key1, Key2),
    Code = raw_chunk(<<"Code">>, Chunks),
    {CodeHeader, _ProtectedBody} = split_code_header(Code),
    DecryptedChunks = rebuild_decrypted_chunks(Chunks, <<CodeHeader/binary, PlainCodeBody/binary>>, PlainLitT),
    Candidate = case beam_lib:build_module([{binary_to_list(Id), Data} || {Id, Data} <- DecryptedChunks]) of
        {ok, BuiltBinary} when is_binary(BuiltBinary) -> BuiltBinary;
        _ -> error({invalid_decrypted_candidate, build_module})
    end,
    validate_decrypted_candidate(Candidate, Module),
    write_binary_exclusive(Output, Candidate),
    io:format("~tp.~n", [#{module => Module,
                            decrypted_chunks => [<<"Code">>, <<"LitT">>],
                            selectors => [Selector1, Selector2],
                            metadata_sha256_matches_plaintext => [Digest1, Digest2],
                            output_bytes => byte_size(Candidate)}]),
    ok.

read_aes_key(Path) ->
    Hex = string:trim(binary_to_list(read_binary(Path))),
    case length(Hex) =:= 64 andalso lists:all(fun is_hex_digit/1, Hex) of
        true -> list_to_binary([hex_byte(A, B) || [A, B] <- pairs(Hex)]);
        false -> error({invalid_aes_key_file, Path})
    end.

is_hex_digit(C) -> (C >= $0 andalso C =< $9) orelse
                   (C >= $a andalso C =< $f) orelse
                   (C >= $A andalso C =< $F).
hex_value(C) when C >= $0, C =< $9 -> C - $0;
hex_value(C) when C >= $a, C =< $f -> C - $a + 10;
hex_value(C) when C >= $A, C =< $F -> C - $A + 10.
hex_byte(A, B) -> (hex_value(A) bsl 4) bor hex_value(B).
pairs([A, B | Rest]) -> [[A, B] | pairs(Rest)];
pairs([]) -> [].

decrypt_envelope(_Id, <<0, 6, "aes128", IV:16/binary, NameSize,
                       Module:NameSize/binary, Selector, Digest:32/binary,
                       Cipher/binary>>, ExpectedModule, Key1, Key2)
  when Module =:= ExpectedModule ->
    Key = case Selector of 1 -> Key1; _ -> Key2 end,
    Plain = crypto:crypto_one_time(aes_256_ctr, Key, IV, Cipher, false),
    {Selector, Plain, crypto:hash(sha256, Plain) =:= Digest};
decrypt_envelope(Id, _Data, _ExpectedModule, _Key1, _Key2) ->
    error({invalid_aes_envelope, Id}).

split_code_header(<<SubSize:32/unsigned-big, _/binary>> = Code)
  when SubSize >= 16, SubSize =< 4096 ->
    HeaderBytes = SubSize + 4,
    case Code of
        <<Header:HeaderBytes/binary, Body/binary>> -> {Header, Body};
        _ -> error(truncated_code_header)
    end;
split_code_header(_) -> error(invalid_code_header).

rebuild_decrypted_chunks(Chunks, Code, LitT) ->
    true = length([ok || {<<"Dbgi">>, _} <- Chunks]) =:= 1,
    true = length([ok || {<<"Abst">>, _} <- Chunks]) =:= 1,
    [case Id of
         <<"Code">> -> {Id, Code};
         <<"LitT">> -> {Id, LitT};
         _ -> {Id, Data}
     end || {Id, Data} <- Chunks, Id =/= <<"Dbgi">>, Id =/= <<"Abst">>].

validate_decrypted_candidate(Candidate, ExpectedModule) ->
    {Facts, Candidate} = container_facts(Candidate),
    [] = maps:get(encrypted_chunks, Facts),
    case beam_lib:all_chunks(Candidate) of
        {ok, ExpectedModule, _} -> ok;
        _ -> error({invalid_decrypted_candidate, beam_lib})
    end,
    Disassembly = try beam_disasm:file(Candidate)
                  catch _:_ -> invalid_disassembly
                  end,
    {Exports, Functions} = case Disassembly of
        {beam_file, ExpectedModule, CandidateExports, _Attrs, _Compile, CandidateFunctions} ->
            {CandidateExports, CandidateFunctions};
        _ -> error({invalid_decrypted_candidate, beam_disasm})
    end,
    EntryLabels = [Entry || {function, _Name, _Arity, Entry, _Instructions} <- Functions],
    true = length(Functions) =:= maps:get(code_function_count, Facts),
    [] = [Label || {_Name, _Arity, Label} <- Exports, not lists:member(Label, EntryLabels)],
    ok.

doctor(Beam) ->
    ensure_modules(),
    {FormatFacts, Binary} = container_facts(read_binary(Beam)),
    ensure_runtime_support(FormatFacts),
    {ok, Module, Chunks} = beam_lib:all_chunks(Binary),
    {beam_file, Module, Exports, _Attrs, _Compile, Functions} = beam_disasm:file(Binary),
    EntryLabels = [Entry || {function, _Name, _Arity, Entry, _Instructions} <- Functions],
    HeaderFunctions = maps:get(code_function_count, FormatFacts),
    MissingExportLabels = [Label || {_Name, _Arity, Label} <- Exports, not lists:member(Label, EntryLabels)],
    Packed = HeaderFunctions =/= length(Functions) orelse MissingExportLabels =/= [],
    Report = FormatFacts#{otp => erlang:system_info(otp_release),
                          erts => erlang:system_info(version),
                          module => Module,
                          chunk_ids => chunk_ids(Chunks),
                          visible_function_count => length(Functions),
                          missing_export_labels => MissingExportLabels,
                          packed_or_protected => Packed},
    io:format("~tp.~n", [Report]),
    ok.

container_facts(Raw) ->
    {Outer, Binary} = unwrap_outer(Raw),
    Chunks = parse_iff(Binary),
    AtomFormat = atom_format(raw_chunk(<<"AtU8">>, Chunks)),
    LiteralFormat = literal_format(optional_raw_chunk(<<"LitT">>, Chunks)),
    Encrypted = [Id || {Id, Data} <- Chunks, aes_envelope(Data)],
    RuntimeLiteralFormat = case lists:member(<<"Abst">>, Encrypted) of
        true -> encrypted_placeholder;
        false -> LiteralFormat
    end,
    MinimumOtp = case {AtomFormat, RuntimeLiteralFormat} of
        {otp28_long_atoms, _} -> 28;
        {_, otp28_uncompressed} -> 28;
        _ -> 27
    end,
    {Labels, Functions} = raw_code_counts(raw_chunk(<<"Code">>, Chunks)),
    {#{outer_container => Outer,
       minimum_otp => MinimumOtp,
       atom_format => AtomFormat,
       literal_format => LiteralFormat,
       encrypted_chunks => Encrypted,
       code_label_count => Labels,
       code_function_count => Functions}, Binary}.

unwrap_outer(<<"FOR1", _/binary>> = Binary) -> {for1, Binary};
unwrap_outer(Raw) ->
    try zlib:gunzip(Raw) of
        <<"FOR1", _/binary>> = Binary -> {gzip, Binary};
        _ -> error(not_a_beam_after_gzip)
    catch
        _:_ -> error(not_a_for1_or_gzip_beam)
    end.

parse_iff(<<"FOR1", Declared:32/unsigned-big, "BEAM", Rest/binary>> = Binary) ->
    true = Declared =:= byte_size(Binary) - 8,
    parse_raw_chunks(Rest, []);
parse_iff(_) -> error(invalid_beam_container).

parse_raw_chunks(<<>>, Acc) -> lists:reverse(Acc);
parse_raw_chunks(<<Id:4/binary, Size:32/unsigned-big, Rest0/binary>>, Acc) ->
    Padding = (4 - (Size rem 4)) rem 4,
    case Rest0 of
        <<Data:Size/binary, _Pad:Padding/binary, Rest/binary>> ->
            parse_raw_chunks(Rest, [{Id, Data} | Acc]);
        _ -> error({truncated_chunk, Id, Size})
    end;
parse_raw_chunks(_, _) -> error(truncated_chunk_header).

raw_chunk(Id, Chunks) ->
    case [Data || {ChunkId, Data} <- Chunks, ChunkId =:= Id] of
        [Data] -> Data;
        [] -> error({missing_chunk, Id});
        _ -> error({duplicate_chunk, Id})
    end.

optional_raw_chunk(Id, Chunks) ->
    case [Data || {ChunkId, Data} <- Chunks, ChunkId =:= Id] of
        [Data] -> Data;
        [] -> missing;
        _ -> error({duplicate_chunk, Id})
    end.

atom_format(<<Count:32/signed-big, _/binary>>) when Count < 0 -> otp28_long_atoms;
atom_format(<<_Count:32/unsigned-big, _/binary>>) -> legacy_short_atoms;
atom_format(_) -> error(invalid_atom_chunk).

literal_format(missing) -> missing;
literal_format(<<0:32, _/binary>>) -> otp28_uncompressed;
literal_format(<<Size:32/unsigned-big, _/binary>>) when Size > 0 -> otp27_zlib_compressed;
literal_format(_) -> error(invalid_literal_chunk).

aes_envelope(<<0, 6, "aes128", _/binary>>) -> true;
aes_envelope(_) -> false.

raw_code_counts(<<_SubSize:32, _InstructionSet:32, _HighestOpcode:32,
                  Labels:32/unsigned-big, Functions:32/unsigned-big, _/binary>>) ->
    {Labels, Functions};
raw_code_counts(_) -> error(invalid_code_header).

ensure_runtime_support(Facts) ->
    Required = maps:get(minimum_otp, Facts),
    Actual = list_to_integer(erlang:system_info(otp_release)),
    case Actual >= Required of
        true -> ok;
        false -> error({runtime_too_old, #{minimum_otp => Required, actual_otp => Actual}})
    end.

%% Test-only internal entry point. It is not exposed by the Bash CLI: its
%% purpose is to feed exact symbolic instructions through the production
%% inventory functions when OTP 27 does not naturally emit legacy opcodes.
forms_fixture(Output) ->
    Functions = [
        {function, synthetic_apply, 0, 1,
         [{label, 1}, {move, {integer, 0}, {x, 0}},
          {move, {atom, erlang}, {x, 1}}, {move, {atom, length}, {x, 2}}, {apply, 1}]},
        {function, synthetic_apply_last, 0, 2,
         [{label, 2}, {move, {integer, 1}, {x, 0}}, {move, {literal, {ok, value}}, {x, 1}},
          {move, {atom, erlang}, {x, 2}}, {move, {atom, element}, {x, 3}}, {apply_last, 2, 0}]},
        {function, synthetic_fun2, 0, 3,
         [{label, 3}, {make_fun2, {synthetic, target, 1}, 0, 0, {x, 0}, {list, []}}, {call_fun2, 1}]}
    ],
    Dependencies = [analyse_function(Function, undefined, #{}) || Function <- Functions],
    Dynamic = lists:append([maps:get(dynamic_calls, Dependency) || Dependency <- Dependencies]),
    write_term_exclusive(Output, #{dependencies => Dependencies, dynamic_calls => Dynamic}),
    ok.

%% Test-only internal entry points. They exercise the same assembly
%% normalizer used by extract, including opcode variants OTP 27 may not emit
%% from this small fixture. They are not exposed by the Bash CLI.
normalization_fixture(Output) ->
    Functions = [
        {function, synthetic_target, 1, 10, [{label, 10}, return]},
        {function, synthetic_call, 0, 20, [{label, 20}, {call, 1, {synthetic, synthetic_target, 1}}]},
        {function, synthetic_call_only, 0, 30, [{label, 30}, {call_only, 1, {synthetic, synthetic_target, 1}}]},
        {function, synthetic_call_last, 0, 40, [{label, 40}, {call_last, 1, {synthetic, synthetic_target, 1}, 0}]},
        {function, synthetic_call_fun2, 0, 50,
         [{label, 50}, {call_fun2, {f, 10}, 1, {tr, {x, 1}, {t_fun, any, any, any}}}]}
    ],
    write_term_exclusive(Output, normalize_lines(synthetic, Functions)),
    ok.

normalization_missing_target() ->
    _ = normalize_lines(synthetic, [{function, synthetic_caller, 0, 1,
        [{label, 1}, {call, 1, {synthetic, absent, 1}}]}]),
    ok.

normalization_missing_fun_label() ->
    _ = normalize_lines(synthetic, [{function, synthetic_caller, 0, 1,
        [{label, 1}, {call_fun2, {f, 999}, 1, {tr, {x, 1}, {t_fun, any, any, any}}}]}]),
    ok.

normalization_invalid_fun_arity() ->
    _ = normalize_lines(synthetic, [
        {function, synthetic_target, 1, 10, [{label, 10}, return]},
        {function, synthetic_caller, 0, 1,
         [{label, 1}, {call_fun2, {f, 10}, 2, {tr, {x, 1}, {t_fun, any, any, any}}}]}
    ]),
    ok.

extract(Beam, Workspace) ->
    ensure_modules(),
    Original = filename:join(Workspace, "original.beam"),
    copy_exclusive(Beam, Original),
    ok = file:change_mode(Original, 8#400),
    {FormatFacts, Binary} = container_facts(read_binary(Beam)),
    ensure_runtime_support(FormatFacts),
    {ok, Module, Chunks} = beam_lib:all_chunks(Binary),
    validate_chunks(Chunks),
    Disassembly = beam_disasm:file(Binary),
    {beam_file, Module, Exports0, Attrs, CompileInfo, Functions0} = Disassembly,
    {LabelCount, FunctionCount} = code_counts(Chunks),
    Exports = [{Name, Arity} || {Name, Arity, _Label} <- Exports0],
    Functions = normalize_lines(Module, Functions0),
    Imports = imports(Beam),
    %% The front end creates this marker before invoking us, so a re-used
    %% workspace is accepted without replacing its safety marker.
    {ok, _Marker} = file:read_file(filename:join(Workspace, ".beam-patch-workspace")),
    write_raw_chunks(filename:join(Workspace, "raw_chunks"), Chunks),
    write_term_exclusive(filename:join(Workspace, "disassembly.term"), Disassembly),
    FunctionInventory = function_inventory(Functions0, CompileInfo),
    {DependencyInventory, DynamicCalls} = dependency_inventory(Functions0, CompileInfo),
    write_term_exclusive(filename:join(Workspace, "functions.term"), {beam_patch_functions, 1, FunctionInventory}),
    write_term_exclusive(filename:join(Workspace, "dependencies.term"), {beam_patch_dependencies, 1, DependencyInventory}),
    write_term_exclusive(filename:join(Workspace, "dynamic_calls.term"), {beam_patch_dynamic_calls, 1, DynamicCalls}),
    Assembly = {beam_patch_assembly, 1, #{module => Module, exports => Exports, attributes => Attrs, label_count => LabelCount, function_count => FunctionCount, functions => Functions}},
    write_term_exclusive(filename:join(Workspace, "editable.S"), Assembly),
    Extras = extra_chunks(Chunks),
    write_term_exclusive(filename:join(Workspace, "extra_chunks.term"), Extras),
    Runtime = runtime_identity(),
    Manifest = #{module => Module, function_count => FunctionCount, label_count => LabelCount, exports => Exports, imports => Imports, attributes => Attrs, on_load => has_on_load(Attrs), chunk_ids => chunk_ids(Chunks), extra_ids => [Id || {Id, _} <- Extras], beam_md5 => md5_hex(Beam), otp_release => erlang:system_info(otp_release), erts_version => erlang:system_info(version), erl_path => maps:get(erl_path, Runtime), escript_path => maps:get(escript_path, Runtime), format_facts => FormatFacts},
    write_term_exclusive(filename:join(Workspace, "manifest.term"), Manifest),
    ok.

roundtrip(AssemblyPath, ExtrasPath, Output, Original) ->
    ok = rebuild(AssemblyPath, ExtrasPath, Output),
    Report = comparison(Original, Output),
    case maps:get(fatal_differences, Report) of
        [] ->
            write_roundtrip_proof(AssemblyPath, ExtrasPath, Output, Original),
            io:format("~tp.~n", [Report]), ok;
        Fatal -> {error, {roundtrip_structural_difference, Fatal}}
    end.

rebuild(AssemblyPath, ExtrasPath, Output) ->
    ensure_modules(),
    Assembly = consult_one(AssemblyPath),
    Extras = consult_one(ExtrasPath),
    {Module, Binary} = assemble_checked(Assembly, Extras),
    write_binary_exclusive(Output, Binary),
    {beam_file, Module, _RebuiltExports, _RebuiltAttrs, _RebuiltCompile, _RebuiltFunctions} = beam_disasm:file(Binary),
    ok.

assemble_checked(Assembly, Extras) ->
    validate_extras(Extras),
    {beam_patch_assembly, 1, Map} = Assembly,
    Module = maps:get(module, Map),
    Exports = maps:get(exports, Map),
    Attrs = maps:get(attributes, Map),
    Labels = maps:get(label_count, Map),
    Functions = maps:get(functions, Map),
    true = is_atom(Module),
    true = is_list(Exports),
    true = is_list(Attrs),
    true = is_integer(Labels),
    true = is_list(Functions),
    validate_function_set(Functions, maps:get(function_count, Map)),
    ModuleCode = case list_to_integer(erlang:system_info(otp_release)) of
        Major when Major >= 29 -> {Module, Exports, Attrs, #{}, Functions, Labels};
        _ -> {Module, Exports, Attrs, Functions, Labels}
    end,
    {ok, Binary} = beam_asm:module(ModuleCode, Extras, [], []),
    {ok, Module, _Chunks} = beam_lib:all_chunks(Binary),
    {beam_file, Module, _RebuiltExports, _RebuiltAttrs, _RebuiltCompile, RebuiltFunctions} = beam_disasm:file(Binary),
    true = length(RebuiltFunctions) =:= length(Functions),
    {Module, Binary}.

validate_function_set(Functions, ExpectedCount) ->
    true = length(Functions) =:= ExpectedCount,
    Identities = [function_identity(Function) || Function <- Functions],
    true = length(Identities) =:= length(lists:usort(Identities)),
    Labels = lists:append([function_labels(Function) || Function <- Functions]),
    PositiveLabels = [Label || Label <- Labels, Label > 0],
    true = length(PositiveLabels) =:= length(lists:usort(PositiveLabels)),
    ok.

function_identity({function, Name, Arity, Entry, Instructions})
  when is_atom(Name), is_integer(Arity), Arity >= 0,
       is_integer(Entry), Entry > 0, is_list(Instructions) ->
    true = lists:member(Entry, [Label || {label, Label} <- Instructions]),
    {Name, Arity, Entry};
function_identity(Other) -> error({invalid_function_term, Other}).

function_labels({function, _Name, _Arity, Entry, Instructions}) ->
    _ = Entry,
    [Label || {label, Label} <- Instructions, is_integer(Label)].

export_function(AssemblyPath, EntryLabelText, Output) ->
    EntryLabel = parse_entry_label(EntryLabelText),
    {beam_patch_assembly, 1, Map} = consult_one(AssemblyPath),
    Module = maps:get(module, Map),
    Functions = maps:get(functions, Map),
    {Name, Arity, Instructions} = selected_function(Functions, EntryLabel),
    Function = {function, Name, Arity, EntryLabel, Instructions},
    Metadata = #{module => Module,
                 name => Name,
                 arity => Arity,
                 entry_label => EntryLabel,
                 source_assembly_digest => sha256_hex(AssemblyPath),
                 owned_labels => function_labels(Function),
                 function => Function},
    write_term_exclusive(Output, {beam_patch_function, 1, Metadata}),
    io:format("export-function selected ~tp/~B entry-label ~B~n", [Name, Arity, EntryLabel]),
    ok.

replace_function(AssemblyPath, FunctionPath, ExtrasPath, Output) ->
    Assembly = {beam_patch_assembly, 1, Map} = consult_one(AssemblyPath),
    {beam_patch_function, 1, Metadata} = consult_one(FunctionPath),
    {Replacement, Name, Arity, EntryLabel} =
        validate_function_wrapper(Metadata, AssemblyPath, Map),
    Functions = maps:get(functions, Map),
    {Name, Arity, _OldInstructions} = selected_function(Functions, EntryLabel),
    UpdatedFunctions = [case Function of
                            {function, Name, Arity, EntryLabel, _} -> Replacement;
                            _ -> Function
                        end || Function <- Functions],
    Updated = {beam_patch_assembly, 1, Map#{functions => UpdatedFunctions}},
    true = assembly_identity(Assembly) =:= assembly_identity(Updated),
    Extras = consult_one(ExtrasPath),
    {_Module, _Binary} = assemble_checked(Updated, Extras),
    write_term_exclusive(Output, Updated),
    io:format("replace-function selected ~tp/~B entry-label ~B; assembly validation passed~n",
              [Name, Arity, EntryLabel]),
    ok.

validate_function_wrapper(Metadata, AssemblyPath, AssemblyMap)
  when is_map(Metadata) ->
    ExpectedKeys = [module, name, arity, entry_label,
                    source_assembly_digest, owned_labels, function],
    ActualKeys = lists:sort(maps:keys(Metadata)),
    case ActualKeys =:= lists:sort(ExpectedKeys) of
        true -> ok;
        false -> error({invalid_function_wrapper_keys,
                        #{expected => lists:sort(ExpectedKeys),
                          actual => ActualKeys}})
    end,
    Module = maps:get(module, Metadata),
    Name = maps:get(name, Metadata),
    Arity = maps:get(arity, Metadata),
    EntryLabel = maps:get(entry_label, Metadata),
    Digest = maps:get(source_assembly_digest, Metadata),
    OwnedLabels = maps:get(owned_labels, Metadata),
    Replacement = maps:get(function, Metadata),
    WrapperIdentity = {Name, Arity, EntryLabel},
    ReplacementIdentity = function_identity(Replacement),
    case ReplacementIdentity =:= WrapperIdentity of
        true -> ok;
        false -> error({function_wrapper_identity_mismatch,
                        #{wrapper => WrapperIdentity,
                          replacement => ReplacementIdentity}})
    end,
    AssemblyModule = maps:get(module, AssemblyMap),
    case Module =:= AssemblyModule of
        true -> ok;
        false -> error({function_wrapper_module_mismatch,
                        #{wrapper => Module, assembly => AssemblyModule}})
    end,
    ActualDigest = sha256_hex(AssemblyPath),
    case Digest =:= ActualDigest of
        true -> ok;
        false -> error({function_wrapper_source_digest_mismatch,
                        #{wrapper => Digest, assembly => ActualDigest}})
    end,
    {Name, Arity, OldInstructions} =
        selected_function(maps:get(functions, AssemblyMap), EntryLabel),
    OldFunction = {function, Name, Arity, EntryLabel, OldInstructions},
    OldLabels = function_labels(OldFunction),
    ReplacementLabels = function_labels(Replacement),
    case is_list(OwnedLabels) andalso
         OwnedLabels =:= OldLabels andalso
         ReplacementLabels =:= OwnedLabels of
        true -> ok;
        false -> error({function_wrapper_label_ownership_mismatch,
                        #{declared => OwnedLabels,
                          source => OldLabels,
                          replacement => ReplacementLabels}})
    end,
    {Replacement, Name, Arity, EntryLabel};
validate_function_wrapper(Other, _AssemblyPath, _AssemblyMap) ->
    error({invalid_function_wrapper, Other}).

rewrite_function_term(AssemblyPath, EntryLabelText, FromPath, ToPath,
                      ExpectedText, ExtrasPath, Output) ->
    EntryLabel = parse_entry_label(EntryLabelText),
    Expected = parse_positive_integer(ExpectedText, expected_count),
    From = consult_one(FromPath),
    To = consult_one(ToPath),
    false = From =:= To,
    Assembly = {beam_patch_assembly, 1, Map} = consult_one(AssemblyPath),
    Functions = maps:get(functions, Map),
    {Name, Arity, Instructions} = selected_function(Functions, EntryLabel),
    {UpdatedInstructions, Count} = rewrite_exact_term(Instructions, From, To),
    case Count =:= Expected of
        true -> ok;
        false -> error({rewrite_match_count, #{expected => Expected, actual => Count,
                                               function => {Name, Arity, EntryLabel}}})
    end,
    UpdatedFunctions =
        [replace_selected_function(Function, EntryLabel, UpdatedInstructions)
         || Function <- Functions],
    Updated = {beam_patch_assembly, 1, Map#{functions => UpdatedFunctions}},
    true = assembly_identity(Assembly) =:= assembly_identity(Updated),
    Extras = consult_one(ExtrasPath),
    {_Module, _Binary} = assemble_checked(Updated, Extras),
    write_term_exclusive(Output, Updated),
    io:format("rewrite-function-term selected ~tp/~B entry-label ~B; exact replacements ~B; assembly validation passed~n",
              [Name, Arity, EntryLabel, Count]),
    ok.

rewrite_exact_term(Term, From, To) when Term =:= From -> {To, 1};
rewrite_exact_term(Term, From, To) when is_tuple(Term) ->
    {Elements, Count} = rewrite_exact_list(tuple_to_list(Term), From, To),
    {list_to_tuple(Elements), Count};
rewrite_exact_term([Head | Tail], From, To) ->
    {NewHead, HeadCount} = rewrite_exact_term(Head, From, To),
    {NewTail, TailCount} = rewrite_exact_term(Tail, From, To),
    {[NewHead | NewTail], HeadCount + TailCount};
rewrite_exact_term([], _From, _To) -> {[], 0};
rewrite_exact_term(Term, From, To) when is_map(Term) ->
    Pairs = maps:to_list(Term),
    {UpdatedPairs, Count} = rewrite_exact_pairs(Pairs, From, To),
    Updated = maps:from_list(UpdatedPairs),
    case map_size(Updated) =:= map_size(Term) of
        true -> {Updated, Count};
        false -> error({rewrite_map_key_collision, Term})
    end;
rewrite_exact_term(Term, _From, _To) -> {Term, 0}.

rewrite_exact_list([], _From, _To) -> {[], 0};
rewrite_exact_list([Head | Tail], From, To) ->
    {NewHead, HeadCount} = rewrite_exact_term(Head, From, To),
    {NewTail, TailCount} = rewrite_exact_list(Tail, From, To),
    {[NewHead | NewTail], HeadCount + TailCount}.

rewrite_exact_pairs([], _From, _To) -> {[], 0};
rewrite_exact_pairs([{Key, Value} | Rest], From, To) ->
    {NewKey, KeyCount} = rewrite_exact_term(Key, From, To),
    {NewValue, ValueCount} = rewrite_exact_term(Value, From, To),
    {NewRest, RestCount} = rewrite_exact_pairs(Rest, From, To),
    {[{NewKey, NewValue} | NewRest], KeyCount + ValueCount + RestCount}.

validate_assembly(AssemblyPath, ExtrasPath) ->
    Assembly = consult_one(AssemblyPath),
    Extras = consult_one(ExtrasPath),
    {Module, Binary} = assemble_checked(Assembly, Extras),
    io:format("validate-assembly module ~tp; bytes ~B; parse and assembly validation passed~n",
              [Module, byte_size(Binary)]),
    ok.

neutral_line_canary(AssemblyPath, EntryLabelText, Output) ->
    EntryLabel = parse_entry_label(EntryLabelText),
    {beam_patch_assembly, 1, Map} = consult_one(AssemblyPath),
    Functions = maps:get(functions, Map),
    {Name, Arity, Instructions} = selected_function(Functions, EntryLabel),
    UpdatedInstructions = remove_first_line(Instructions, EntryLabel),
    UpdatedFunctions = [replace_selected_function(Function, EntryLabel, UpdatedInstructions) || Function <- Functions],
    write_term_exclusive(Output, {beam_patch_assembly, 1, Map#{functions => UpdatedFunctions}}),
    io:format("neutral-line-canary selected ~tp/~B entry-label ~B~n", [Name, Arity, EntryLabel]),
    ok.

validate_roundtrip_proof(Workspace) ->
    ensure_modules(),
    ProofPath = filename:join(Workspace, ".roundtrip-verified.term"),
    {beam_patch_roundtrip_verified, 1, Proof} = consult_one(ProofPath),
    Original = filename:join(Workspace, "original.beam"),
    Editable = filename:join(Workspace, "editable.S"),
    Extras = filename:join(Workspace, "extra_chunks.term"),
    Roundtrip = filename:join(Workspace, "roundtrip.beam"),
    Facts = facts(Original),
    Runtime = runtime_identity(),
    Expected = #{original_sha256 => sha256_hex(Original), editable_sha256 => sha256_hex(Editable), extra_chunks_sha256 => sha256_hex(Extras), roundtrip_sha256 => sha256_hex(Roundtrip), module => maps:get(module, Facts), otp_release => erlang:system_info(otp_release), erts_version => erlang:system_info(version), erl_path => maps:get(erl_path, Runtime), escript_path => maps:get(escript_path, Runtime)},
    validate_proof_fields(maps:to_list(Expected), Proof),
    ok.

validate_edited_assembly(BaselinePath, EditedPath) ->
    Baseline = assembly_identity(consult_one(BaselinePath)),
    Edited = assembly_identity(consult_one(EditedPath)),
    case Baseline =:= Edited of
        true -> ok;
        false -> error({edited_assembly_identity_mismatch, Baseline, Edited})
    end.

verify(Original, Candidate) ->
    Report = comparison(Original, Candidate),
    io:format("~tp.~n", [Report]),
    case maps:get(fatal_differences, Report) of [] -> ok; Fatal -> {error, {fatal_differences, Fatal}} end.

comparison(Original, Candidate) ->
    A = facts(Original), B = facts(Candidate),
    Keys = [module, function_count, exports, imports],
    Fatal = [{Key, maps:get(Key, A), maps:get(Key, B)} || Key <- Keys, maps:get(Key, A) =/= maps:get(Key, B)],
    Expected = [{chunk_ids, maps:get(chunk_ids, A), maps:get(chunk_ids, B)}, {beam_md5, maps:get(beam_md5, A), maps:get(beam_md5, B)}],
    #{original => A, candidate => B, fatal_differences => Fatal, expected_differences => Expected}.

write_roundtrip_proof(AssemblyPath, ExtrasPath, Output, Original) ->
    Workspace = filename:dirname(AssemblyPath),
    Facts = facts(Original),
    Runtime = runtime_identity(),
    Proof = #{original_sha256 => sha256_hex(Original), editable_sha256 => sha256_hex(AssemblyPath), extra_chunks_sha256 => sha256_hex(ExtrasPath), roundtrip_sha256 => sha256_hex(Output), module => maps:get(module, Facts), otp_release => erlang:system_info(otp_release), erts_version => erlang:system_info(version), erl_path => maps:get(erl_path, Runtime), escript_path => maps:get(escript_path, Runtime)},
    write_term_exclusive(filename:join(Workspace, ".roundtrip-verified.term"), {beam_patch_roundtrip_verified, 1, Proof}).

validate_proof_fields([], _Proof) -> ok;
validate_proof_fields([{Key, Expected} | Rest], Proof) ->
    Actual = maps:get(Key, Proof, missing),
    case Actual =:= Expected of
        true -> validate_proof_fields(Rest, Proof);
        false -> error({roundtrip_proof_mismatch, Key, Expected, Actual})
    end.

runtime_identity() ->
    ErlPath = os:getenv("BEAM_TOOLKIT_ERL_PATH"),
    EscriptPath = os:getenv("BEAM_TOOLKIT_ESCRIPT_PATH"),
    true = is_list(ErlPath) andalso ErlPath =/= [],
    true = is_list(EscriptPath) andalso EscriptPath =/= [],
    #{erl_path => ErlPath, escript_path => EscriptPath}.

assembly_identity({beam_patch_assembly, 1, Map}) ->
    #{module => maps:get(module, Map), exports => maps:get(exports, Map), function_count => maps:get(function_count, Map), label_count => maps:get(label_count, Map)}.

parse_entry_label(Text) ->
    parse_positive_integer(Text, entry_label).

parse_positive_integer(Text, Kind) ->
    case string:to_integer(Text) of
        {Label, []} when is_integer(Label), Label > 0 -> Label;
        _ -> error({invalid_positive_integer, Kind, Text})
    end.

selected_function(Functions, EntryLabel) ->
    Matches = [{Name, Arity, Instructions} || {function, Name, Arity, Label, Instructions} <- Functions, Label =:= EntryLabel],
    case Matches of
        [Match] -> Match;
        [] -> error({entry_label_not_found, EntryLabel});
        _ -> error({duplicate_entry_label, EntryLabel})
    end.

remove_first_line([], EntryLabel) -> error({no_line_marker, EntryLabel});
remove_first_line([{line, _} | Rest], _EntryLabel) -> Rest;
remove_first_line([Instruction | Rest], EntryLabel) -> [Instruction | remove_first_line(Rest, EntryLabel)].

replace_selected_function({function, Name, Arity, EntryLabel, _Instructions}, EntryLabel, UpdatedInstructions) ->
    {function, Name, Arity, EntryLabel, UpdatedInstructions};
replace_selected_function(Function, _EntryLabel, _UpdatedInstructions) -> Function.

facts(Path) ->
    Binary = read_binary(Path),
    {ok, Module, Chunks} = beam_lib:all_chunks(Binary),
    {beam_file, Module, Exports0, Attrs, _CompileInfo, Functions} = beam_disasm:file(Binary),
    {Labels, FunctionCount} = code_counts(Chunks),
    Extras = extra_chunks(Chunks),
    #{module => Module, function_count => FunctionCount, disassembled_function_count => length(Functions), label_count => Labels, exports => [{N, A} || {N, A, _} <- Exports0], imports => imports(Path), attributes => Attrs, on_load => has_on_load(Attrs), chunk_ids => chunk_ids(Chunks), extra_ids => [Id || {Id, _} <- Extras], sha256 => sha256_hex(Path), beam_md5 => md5_hex(Path)}.

ensure_modules() ->
    lists:foreach(fun(Module) -> {module, Module} = code:ensure_loaded(Module) end, [beam_lib, beam_disasm, beam_asm, crypto]), ok.

code_counts(Chunks) ->
    Code = proplists:get_value("Code", Chunks),
    <<16:32, _InstructionSet:32, _HighestOpcode:32, LabelCount:32, FunctionCount:32, _/binary>> = Code,
    {LabelCount, FunctionCount}.

normalize_lines(Module, Functions) ->
    FunLabels = maps:from_list([{{Name, Arity}, Label} || {function, Name, Arity, Label, _Instructions} <- Functions]),
    EntryTargets = maps:from_list([{Label, {Name, Arity}} || {function, Name, Arity, Label, _Instructions} <- Functions]),
    [{function, Name, Arity, Label, [normalize_instruction(Instruction, Module, FunLabels, EntryTargets) || Instruction <- Instructions]} || {function, Name, Arity, Label, Instructions} <- Functions].

normalize_instruction({line, _}, _Module, _FunLabels, _EntryTargets) -> {line, []};
normalize_instruction({make_fun3, {Module, Function, Arity}, _OldIndex, _Uniq, Destination, Environment}, Module, FunLabels, _EntryTargets) ->
    {make_fun3, local_label(Module, Function, Arity, FunLabels), 0, 0, Destination, Environment};
normalize_instruction({make_fun2, {Module, Function, Arity}, _OldIndex, _Uniq, Destination, Environment}, Module, FunLabels, _EntryTargets) ->
    {make_fun2, local_label(Module, Function, Arity, FunLabels), 0, 0, Destination, Environment};
normalize_instruction({call, Arity, {Module, Function, Arity}}, Module, FunLabels, _EntryTargets) ->
    {call, Arity, local_label(Module, Function, Arity, FunLabels)};
normalize_instruction({call_only, Arity, {Module, Function, Arity}}, Module, FunLabels, _EntryTargets) ->
    {call_only, Arity, local_label(Module, Function, Arity, FunLabels)};
normalize_instruction({call_last, Arity, {Module, Function, Arity}, Deallocate}, Module, FunLabels, _EntryTargets) ->
    {call_last, Arity, local_label(Module, Function, Arity, FunLabels), Deallocate};
normalize_instruction({bif, Name, nofail, Arguments, Destination}, _Module, _FunLabels, _EntryTargets) ->
    {bif, Name, {f, 0}, Arguments, Destination};
normalize_instruction({call_fun2, {f, Label}, CallArity, {tr, Register, {t_fun, _ArityField, any, TypeField}}}, _Module, _FunLabels, EntryTargets) ->
    {TargetName, TotalArity} = fun_entry_target(Label, EntryTargets),
    case TotalArity >= CallArity of
        true -> {call_fun2, {f, Label}, CallArity, {tr, Register, {t_fun, CallArity, {TargetName, TotalArity}, TypeField}}};
        false -> error({invalid_fun_target_arity, {Label, TotalArity, CallArity}})
    end;
normalize_instruction(Instruction, _Module, _FunLabels, _EntryTargets) -> Instruction.

local_label(Module, Function, Arity, FunLabels) ->
    case maps:find({Function, Arity}, FunLabels) of
        {ok, EntryLabel} -> {f, EntryLabel};
        error -> error({missing_local_target, {Module, Function, Arity}})
    end.

fun_entry_target(Label, EntryTargets) ->
    case maps:find(Label, EntryTargets) of
        {ok, Target} -> Target;
        error -> error({missing_fun_entry_label, Label})
    end.

%% Complete, unfiltered function inventory. beam_disasm does not expose byte
%% offsets; line locations are reported only when its Line metadata provides
%% them, and the compile-info source filename is retained when available.
function_inventory(Functions, CompileInfo) ->
    Source = proplists:get_value(source, CompileInfo, undefined),
    [function_record(Function, Source) || Function <- Functions].

function_record({function, Name, Arity, EntryLabel, Instructions}, Source) ->
    Labels = [Label || {label, Label} <- Instructions],
    #{name => Name, arity => Arity, entry_label => EntryLabel, labels => Labels,
      label_span => label_span(Labels), instruction_count => length(Instructions),
      locations => locations(Instructions, Source)}.

label_span([]) -> undefined;
label_span(Labels) -> {lists:min(Labels), lists:max(Labels)}.

locations(Instructions, Source) ->
    [#{source => Source, metadata => Metadata} || {line, Metadata} <- Instructions].

dependency_inventory(Functions, CompileInfo) ->
    Source = proplists:get_value(source, CompileInfo, undefined),
    EntryIndex = maps:from_list([{Entry, {Name, Arity}} || {function, Name, Arity, Entry, _} <- Functions]),
    Analyses = [analyse_function(Function, Source, EntryIndex) || Function <- Functions],
    {Analyses, lists:append([maps:get(dynamic_calls, Analysis) || Analysis <- Analyses])}.

analyse_function({function, Name, Arity, _Entry, Instructions}, Source, EntryIndex) ->
    {Local, External, Bifs, Funs, Dynamic0, Forms, Unclassified} =
        scan_instructions(Instructions, {Name, Arity}, Source, EntryIndex, #{}, undefined, undefined, {[], [], [], [], [], [], []}),
    Dynamic = conservatively_join_dynamic(Instructions, lists:reverse(Dynamic0)),
    #{name => Name, arity => Arity,
      local_calls => lists:reverse(Local), external_calls => lists:reverse(External),
      bifs => lists:reverse(Bifs), fun_references => lists:reverse(Funs),
      unresolved_dynamic_calls => [Call || Call <- Dynamic, maps:get(certainty, maps:get(resolution, Call)) =:= unresolved],
      dynamic_calls => Dynamic, instruction_forms => lists:usort(Forms),
      unclassified_dependency_instructions => lists:reverse(Unclassified)}.

%% The scan intentionally does not construct a CFG. If a function contains a
%% split/jump/exception boundary, do not call any dynamic target exact unless a
%% CFG join has proven all predecessors. This is stricter than necessary but
%% safe; the available target fields preserve useful evidence.
conservatively_join_dynamic(Instructions, Dynamic) ->
    case lists:any(fun is_control_flow_boundary/1, Instructions) of
        false -> Dynamic;
        true -> [downgrade_exact_dynamic(Call) || Call <- Dynamic]
    end.

is_control_flow_boundary({jump, _}) -> true;
is_control_flow_boundary({select_val, _, _, _}) -> true;
is_control_flow_boundary({select_tuple_arity, _, _, _}) -> true;
is_control_flow_boundary({test, _, _, _}) -> true;
is_control_flow_boundary({test, _, _, _, _}) -> true;
is_control_flow_boundary({'try', _}) -> true;
is_control_flow_boundary({'catch', _}) -> true;
is_control_flow_boundary({loop_rec, _}) -> true;
is_control_flow_boundary({loop_rec_end, _}) -> true;
is_control_flow_boundary(_) -> false.

downgrade_exact_dynamic(#{resolution := #{certainty := exact, target := {Module, Function, Arity}} = Resolution} = Call) ->
    Available = #{module => Module, function => Function, argument_arity => Arity},
    Call#{resolution => Resolution#{certainty => unresolved, reason => control_flow_join_not_proven, available => Available}};
downgrade_exact_dynamic(Call) -> Call.

scan_instructions([], _Caller, _Source, _Entries, _State, _Label, _Line, Acc) -> Acc;
scan_instructions([Instruction | Rest], Caller, Source, Entries, State0, Label0, Line0, Acc0) ->
    Forms0 = add_form(Instruction, Acc0),
    case Instruction of
        %% A label is a control-flow join. A linear scan cannot prove that all
        %% predecessors agree, so discard facts rather than manufacture exactness.
        {label, Label} -> scan_instructions(Rest, Caller, Source, Entries, #{}, Label, Line0, Forms0);
        %% OTP 29 may expose richer line metadata rather than a bare integer.
        %% Line annotations do not mutate registers, so facts cross them.
        {line, Line} -> scan_instructions(Rest, Caller, Source, Entries, State0, Label0, Line, Forms0);
        {move, SourceOperand, Destination} ->
            scan_instructions(Rest, Caller, Source, Entries, put_value(Destination, operand_value(SourceOperand, State0), State0), Label0, Line0, Forms0);
        {make_fun3, {Module, Function, TargetArity}, _OldIndex, _Uniq, Destination, _Environment} ->
            Ref = #{target => {Module, Function, TargetArity}, location => call_location(Label0, Line0, Source)},
            Acc1 = add_fun_reference(Ref, Forms0),
            scan_instructions(Rest, Caller, Source, Entries, put_value(Destination, {funref, {Module, Function, TargetArity}}, State0), Label0, Line0, Acc1);
        {make_fun2, {Module, Function, TargetArity}, _Index, _Uniq, Destination, _Environment} ->
            Ref = #{target => {Module, Function, TargetArity}, location => call_location(Label0, Line0, Source)},
            Acc1 = add_fun_reference(Ref, Forms0),
            scan_instructions(Rest, Caller, Source, Entries, put_value(Destination, {funref, {Module, Function, TargetArity}}, State0), Label0, Line0, Acc1);
        {call, CallArity, Target} ->
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_local_call(Target, CallArity, Entries, Label0, Line0, Source, Forms0));
        {call_only, CallArity, Target} ->
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_local_call(Target, CallArity, Entries, Label0, Line0, Source, Forms0));
        {call_last, CallArity, Target, _Deallocate} ->
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_local_call(Target, CallArity, Entries, Label0, Line0, Source, Forms0));
        {call_ext, CallArity, {extfunc, Module, Function, _TargetArity}} ->
            scan_external(Rest, Caller, Source, Entries, State0, Label0, Line0, Forms0, Module, Function, CallArity);
        {call_ext_only, CallArity, {extfunc, Module, Function, _TargetArity}} ->
            scan_external(Rest, Caller, Source, Entries, State0, Label0, Line0, Forms0, Module, Function, CallArity);
        {call_ext_last, CallArity, {extfunc, Module, Function, _TargetArity}, _Deallocate} ->
            scan_external(Rest, Caller, Source, Entries, State0, Label0, Line0, Forms0, Module, Function, CallArity);
        {bif, Bif, _Fail, Arguments, _Destination} ->
            Entry = #{bif => Bif, arguments => Arguments, location => call_location(Label0, Line0, Source)},
            scan_instructions(Rest, Caller, Source, Entries, State0, Label0, Line0, add_bif(Entry, Forms0));
        {gc_bif, Bif, _Fail, _Live, Arguments, _Destination} ->
            Entry = #{bif => Bif, arguments => Arguments, location => call_location(Label0, Line0, Source)},
            scan_instructions(Rest, Caller, Source, Entries, State0, Label0, Line0, add_bif(Entry, Forms0));
        {apply, ApplyArity} ->
            Dynamic = dynamic_apply_instruction(apply, ApplyArity, Caller, State0, Label0, Line0, Source),
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_dynamic(Dynamic, Forms0));
        {apply_last, ApplyArity, _Deallocate} ->
            Dynamic = dynamic_apply_instruction(apply_last, ApplyArity, Caller, State0, Label0, Line0, Source),
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_dynamic(Dynamic, Forms0));
        {call_fun, CallArity} ->
            Dynamic = dynamic_fun_instruction(call_fun, CallArity, Caller, State0, Label0, Line0, Source),
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_dynamic(Dynamic, Forms0));
        {call_fun2, CallArity} ->
            Dynamic = dynamic_fun_instruction(call_fun2, CallArity, Caller, State0, Label0, Line0, Source),
            scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State0), Label0, Line0, add_dynamic(Dynamic, Forms0));
        _ ->
            %% Opaque instructions can branch, mutate registers, or both. Their
            %% form remains inventoried, but no propagated fact crosses them.
            scan_instructions(Rest, Caller, Source, Entries, #{}, Label0, Line0, add_unclassified(Instruction, Forms0))
    end.

scan_external(Rest, Caller, Source, Entries, State, Label, Line, Acc, erlang, apply, 2) ->
    Dynamic = dynamic_external_apply(2, Caller, State, Label, Line, Source),
    scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State), Label, Line, add_dynamic(Dynamic, add_external_call({erlang, apply, 2}, Label, Line, Source, Acc)));
scan_external(Rest, Caller, Source, Entries, State, Label, Line, Acc, erlang, apply, 3) ->
    Dynamic = dynamic_external_apply(3, Caller, State, Label, Line, Source),
    scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State), Label, Line, add_dynamic(Dynamic, add_external_call({erlang, apply, 3}, Label, Line, Source, Acc)));
scan_external(Rest, Caller, Source, Entries, State, Label, Line, Acc, Module, Function, Arity) ->
    scan_instructions(Rest, Caller, Source, Entries, clear_call_result(State), Label, Line, add_external_call({Module, Function, Arity}, Label, Line, Source, Acc)).

dynamic_external_apply(2, Caller, State, Label, Line, Source) -> resolve_fun_apply(Caller, State, Label, Line, Source, erlang_apply_2);
dynamic_external_apply(3, Caller, State, Label, Line, Source) -> resolve_mfa_apply(Caller, State, Label, Line, Source, erlang_apply_3).
dynamic_apply_instruction(Instruction, ApplyArity, Caller, State, Label, Line, Source) -> resolve_beam_apply(Instruction, ApplyArity, Caller, State, Label, Line, Source).
dynamic_fun_instruction(Kind, CallArity, Caller, State, Label, Line, Source) ->
    Resolution = case maps:get({x, 0}, State, unknown) of
        {funref, Target} -> #{certainty => exact, target => Target, argument_arity => CallArity};
        _ -> #{certainty => unresolved, reason => fun_value_not_provable, available => #{argument_arity => CallArity}}
    end,
    #{caller => element(1, Caller), caller_arity => element(2, Caller), kind => Kind, instruction => Kind, location => call_location(Label, Line, Source), resolution => Resolution}.

resolve_fun_apply(Caller, State, Label, Line, Source, Kind) ->
    Fun = maps:get({x, 0}, State, unknown), Args = maps:get({x, 1}, State, unknown),
    Resolution = case {Fun, list_arity(Args)} of
        {{funref, Target}, {known, Count}} -> #{certainty => exact, target => Target, argument_arity => Count};
        {{funref, Target}, unknown} -> #{certainty => partial, target => Target, reason => argument_list_not_provable};
        {unknown, {known, Count}} -> #{certainty => unresolved, reason => fun_value_not_provable, available => #{argument_arity => Count}};
        _ -> #{certainty => unresolved, reason => fun_and_argument_list_not_provable}
    end,
    #{caller => element(1, Caller), caller_arity => element(2, Caller), kind => Kind, instruction => {erlang, apply, 2}, location => call_location(Label, Line, Source), resolution => Resolution}.

resolve_mfa_apply(Caller, State, Label, Line, Source, Kind) ->
    Module = maps:get({x, 0}, State, unknown), Function = maps:get({x, 1}, State, unknown), Args = maps:get({x, 2}, State, unknown),
    Resolution = case {Module, Function, list_arity(Args)} of
        {{atom, M}, {atom, F}, {known, Count}} -> #{certainty => exact, target => {M, F, Count}};
        _ -> partial_mfa_resolution(Module, Function, list_arity(Args))
    end,
    #{caller => element(1, Caller), caller_arity => element(2, Caller), kind => Kind, instruction => {erlang, apply, 3}, location => call_location(Label, Line, Source), resolution => Resolution}.

partial_mfa_resolution(Module, Function, Arity) ->
    Available0 = case Module of {atom, M} -> #{module => M}; _ -> #{} end,
    Available1 = case Function of {atom, F} -> Available0#{function => F}; _ -> Available0 end,
    Available = case Arity of {known, Count} -> Available1#{argument_arity => Count}; _ -> Available1 end,
    case map_size(Available) of
        0 -> #{certainty => unresolved, reason => module_function_and_argument_list_runtime_values};
        _ -> #{certainty => partial, reason => module_or_function_runtime_value, available => Available}
    end.

%% BEAM apply/apply_last carry the number of positional arguments, not an
%% Erlang argument-list register. The module and function follow those values.
resolve_beam_apply(Instruction, ApplyArity, Caller, State, Label, Line, Source) when is_integer(ApplyArity), ApplyArity >= 0 ->
    Module = maps:get({x, ApplyArity}, State, unknown),
    Function = maps:get({x, ApplyArity + 1}, State, unknown),
    Resolution = case {Module, Function} of
        {{atom, M}, {atom, F}} -> #{certainty => exact, target => {M, F, ApplyArity}};
        _ -> partial_mfa_resolution(Module, Function, {known, ApplyArity})
    end,
    #{caller => element(1, Caller), caller_arity => element(2, Caller), kind => beam_apply,
      instruction => {Instruction, ApplyArity}, location => call_location(Label, Line, Source), resolution => Resolution}.

list_arity({literal, List}) when is_list(List) -> {known, length(List)};
list_arity(List) when is_list(List) -> {known, length(List)};
list_arity(_) -> unknown.

operand_value({atom, Value}, _State) -> {atom, Value};
operand_value({integer, Value}, _State) -> {integer, Value};
operand_value({literal, Value}, _State) -> {literal, Value};
operand_value(nil, _State) -> {literal, []};
operand_value({x, _} = Register, State) -> maps:get(Register, State, unknown);
operand_value({y, _} = Register, State) -> maps:get(Register, State, unknown);
operand_value(_, _State) -> unknown.
put_value({x, _} = Register, Value, State) -> State#{Register => Value};
put_value({y, _} = Register, Value, State) -> State#{Register => Value};
put_value(_Destination, _Value, State) -> State.
clear_call_result(State) -> maps:remove({x, 0}, State).
call_location(Label, Line, Source) -> #{label => Label, source => Source, line => Line}.

add_form(Instruction, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) ->
    {Local, External, Bifs, Funs, Dynamic, [instruction_form(Instruction) | Forms], Unclassified}.
instruction_form(Instruction) when is_atom(Instruction) -> Instruction;
instruction_form(Instruction) when is_tuple(Instruction) -> element(1, Instruction);
instruction_form(_) -> unknown.
add_local_call(Target, Arity, Entries, Label, Line, Source, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) ->
    Resolved = case Target of {f, TargetLabel} -> maps:get(TargetLabel, Entries, {unresolved_label, TargetLabel}); {M, F, TargetArity} -> {M, F, TargetArity}; _ -> Target end,
    {[#{target => Resolved, call_arity => Arity, location => call_location(Label, Line, Source)} | Local], External, Bifs, Funs, Dynamic, Forms, Unclassified}.
add_external_call(MFA, Label, Line, Source, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) ->
    {Local, [#{target => MFA, location => call_location(Label, Line, Source)} | External], Bifs, Funs, Dynamic, Forms, Unclassified}.
add_bif(Entry, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) -> {Local, External, [Entry | Bifs], Funs, Dynamic, Forms, Unclassified}.
add_fun_reference(Entry, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) -> {Local, External, Bifs, [Entry | Funs], Dynamic, Forms, Unclassified}.
add_dynamic(Entry, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) -> {Local, External, Bifs, Funs, [Entry | Dynamic], Forms, Unclassified}.
add_unclassified(Instruction, {Local, External, Bifs, Funs, Dynamic, Forms, Unclassified}) -> {Local, External, Bifs, Funs, Dynamic, Forms, [Instruction | Unclassified]}.

imports(Path) ->
    {ok, {_Module, [{imports, Imports}]}} = beam_lib:chunks(read_binary(Path), [imports]),
    Imports.

has_on_load(Attrs) -> lists:keymember(on_load, 1, Attrs).

chunk_ids(Chunks) -> [list_to_binary(Id) || {Id, _} <- Chunks].
regenerated_ids() -> [<<"Atom">>, <<"AtU8">>, <<"Code">>, <<"StrT">>, <<"ImpT">>, <<"ExpT">>, <<"LocT">>, <<"FunT">>, <<"LitT">>, <<"Attr">>, <<"CInf">>, <<"Dbgi">>, <<"Abst">>, <<"Line">>, <<"Type">>, <<"Docs">>, <<"DbgB">>, <<"Recs">>].

extra_chunks(Chunks) ->
    [{list_to_binary(Id), Bin} || {Id, Bin} <- Chunks, not lists:member(list_to_binary(Id), regenerated_ids())].

validate_chunks(Chunks) ->
    Ids = chunk_ids(Chunks),
    true = lists:all(fun(Id) -> byte_size(Id) =:= 4 end, Ids),
    true = length(Ids) =:= length(lists:usort(Ids)),
    ok.

validate_extras(Extras) ->
    true = is_list(Extras),
    Ids = [Id || {Id, Bin} <- Extras, is_binary(Id), byte_size(Id) =:= 4, is_binary(Bin)],
    true = length(Ids) =:= length(Extras),
    true = length(Ids) =:= length(lists:usort(Ids)),
    true = lists:all(fun(Id) -> not lists:member(Id, regenerated_ids()) end, Ids),
    ok.

write_raw_chunks(Directory, Chunks) ->
    ok = file:make_dir(Directory),
    lists:foreach(fun({Index, {_Id, Bin}}) -> write_binary_exclusive(filename:join(Directory, io_lib:format("~4..0B.bin", [Index])), Bin) end, lists:zip(lists:seq(1, length(Chunks)), Chunks)),
    ok.

flow_static(Output, ScopeText, BeamCountText, DirCountText, Paths) ->
    Scope = flow_scope(ScopeText),
    BeamCount = decimal_integer(BeamCountText),
    DirCount = decimal_integer(DirCountText),
    true = BeamCount >= 0,
    true = DirCount >= 0,
    true = length(Paths) =:= BeamCount + DirCount,
    {Beams, Directories} = lists:split(BeamCount, Paths),
    DiscoveredBeams = discover_inputs(Scope, Beams, Directories),
    Config = #{schema => beam_flow_config_v1,
               mode => static,
               scope => Scope,
               requested_beams => Beams,
               requested_beam_directories => Directories,
               discovered_beams => DiscoveredBeams},
    Provenance = #{otp_release => erlang:system_info(otp_release),
                   erts_version => erlang:system_info(version),
                   erl_path => getenv_required("BEAM_TOOLKIT_ERL_PATH"),
                   escript_path => getenv_required("BEAM_TOOLKIT_ESCRIPT_PATH")},
    ModuleGraphs0 = [build_module_cfg(Beam, Ordinal)
                     || {Beam, Ordinal} <- lists:zip(
                          DiscoveredBeams,
                          lists:seq(1, length(DiscoveredBeams)))],
    ModuleGraphs = validate_unique_modules(ModuleGraphs0),
    Graph = validate_cfg(merge_module_cfgs(ModuleGraphs)),
    Functions = maps:get(functions, Graph),
    Blocks = maps:get(blocks, Graph),
    Instructions = maps:get(instructions, Graph),
    CfgEdges = maps:get(cfg_edges, Graph),
    Unsupported = maps:get(unsupported, Graph),
    {BlockStates, DynamicCalls} = analyze_cfg(Graph),
    Modules = module_records(ModuleGraphs),
    {Callsites, CallEdges, Unresolved} = build_callgraph(
      Graph, DynamicCalls, Modules),
    Components = strong_components(Functions, CallEdges),
    Counts = #{modules => length(ModuleGraphs),
               functions => length(Functions),
               blocks => length(Blocks),
               instructions => length(Instructions),
               cfg_edges => length(CfgEdges),
               block_states => length(BlockStates),
               callsites => length(Callsites),
               call_edges => length(CallEdges),
               unresolved => length(Unresolved),
               unsupported => length(Unsupported)},
    FlowIR0 = #{schema => beam_flow_ir_v1,
                state => complete,
                provenance => Provenance,
                modules => Modules,
                functions => Functions,
                blocks => Blocks,
                instructions => Instructions,
                cfg_edges => CfgEdges,
                block_states => BlockStates,
                dynamic_calls => DynamicCalls,
                callsites => Callsites,
                call_edges => CallEdges,
                strongly_connected_components => Components,
                unresolved => Unresolved,
                unsupported => Unsupported,
                runtime => undefined,
                counts => Counts},
    FlowIR = validate_flow_ir(FlowIR0),
    Manifest = #{schema => beam_flow_ir_v1,
                 state => complete,
                 mode => static,
                 scope => Scope,
                 provenance => Provenance,
                 counts => Counts},
    write_term_exclusive(filename:join(Output, "flow-config.term"), Config),
    write_term_exclusive(filename:join(Output, "functions.term"), Functions),
    write_term_exclusive(filename:join(Output, "blocks.term"), Blocks),
    write_term_exclusive(filename:join(Output, "instructions.term"), Instructions),
    write_term_exclusive(filename:join(Output, "cfg-edges.term"), CfgEdges),
    write_term_exclusive(filename:join(Output, "block-states.term"), BlockStates),
    write_term_exclusive(filename:join(Output, "dynamic-calls.term"), DynamicCalls),
    write_term_exclusive(filename:join(Output, "modules.term"), Modules),
    write_term_exclusive(filename:join(Output, "callsites.term"), Callsites),
    write_term_exclusive(filename:join(Output, "callgraph.term"),
                         #{call_edges => CallEdges,
                           strongly_connected_components => Components}),
    write_term_exclusive(filename:join(Output, "unresolved.term"), Unresolved),
    write_term_exclusive(filename:join(Output, "flow-ir.term"), FlowIR),
    write_json(filename:join(Output, "flow-ir.json"), FlowIR),
    write_callgraph_dot(filename:join(Output, "callgraph.dot"), FlowIR),
    write_graphml(filename:join(Output, "callgraph.graphml"), FlowIR),
    write_cfg_dots(Output, FlowIR),
    write_flow_html(filename:join(Output, "flow.html"), FlowIR),
    write_term_exclusive(filename:join(Output, "unsupported.term"), Unsupported),
    write_term_exclusive(filename:join(Output, "flow-manifest.term"), Manifest),
    ok.

flow_scope("single") -> single;
flow_scope("supplied") -> supplied;
flow_scope("tree") -> tree;
flow_scope(Other) -> error({invalid_flow_scope, Other}).

discover_inputs(single, [Beam], []) ->
    [validate_beam_input(Beam)];
discover_inputs(single, Beams, Directories) ->
    error({invalid_single_scope_inputs, length(Beams), length(Directories)});
discover_inputs(supplied, Beams, Directories) ->
    Discovered = Beams ++ lists:append([immediate_beams(Directory)
                                        || Directory <- Directories]),
    validate_discovered_inputs(Discovered);
discover_inputs(tree, Beams, Directories) ->
    Discovered = Beams ++ lists:append([recursive_beams(Directory)
                                        || Directory <- Directories]),
    validate_discovered_inputs(Discovered).

validate_discovered_inputs(Paths) ->
    Unique = lists:usort(Paths),
    true = Unique =/= [],
    [validate_beam_input(Path) || Path <- Unique].

validate_beam_input(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = regular}} -> Path;
        {ok, #file_info{type = symlink}} -> error({symlink_beam_input, Path});
        {ok, #file_info{type = Type}} -> error({non_regular_beam_input, Path, Type});
        {error, Reason} -> error({unreadable_beam_input, Path, Reason})
    end.

immediate_beams(Directory) ->
    case file:list_dir(Directory) of
        {ok, Names} ->
            [validate_beam_input(filename:join(Directory, Name))
             || Name <- lists:sort(Names),
                filename:extension(Name) =:= ".beam"];
        {error, Reason} -> error({beam_directory_unreadable, Directory, Reason})
    end.

recursive_beams(Directory) ->
    recursive_beams(Directory, []).

recursive_beams(Directory, Acc) ->
    case file:list_dir(Directory) of
        {ok, Names} ->
            lists:foldl(fun(Name, Current) ->
                Path = filename:join(Directory, Name),
                case file:read_link_info(Path) of
                    {ok, #file_info{type = symlink}} ->
                        error({symlink_in_beam_tree, Path});
                    {ok, #file_info{type = directory}} ->
                        recursive_beams(Path, Current);
                    {ok, #file_info{type = regular}} ->
                        case filename:extension(Name) of
                            ".beam" -> [Path | Current];
                            _ -> Current
                        end;
                    {ok, _Other} -> Current;
                    {error, Reason} -> error({beam_tree_entry_unreadable, Path, Reason})
                end
            end, Acc, lists:sort(Names));
        {error, Reason} -> error({beam_tree_unreadable, Directory, Reason})
    end.

validate_unique_modules(ModuleGraphs) ->
    Modules = [maps:get(module, Graph) || Graph <- ModuleGraphs],
    case length(Modules) =:= length(lists:usort(Modules)) of
        true -> ModuleGraphs;
        false -> error({duplicate_module_identity, duplicate_values(Modules)})
    end.

duplicate_values(Values) ->
    lists:usort([Value || Value <- Values,
                          length([Same || Same <- Values, Same =:= Value]) > 1]).

module_records(ModuleGraphs) ->
    [#{id => {module, maps:get(module, Graph)},
       module => maps:get(module, Graph),
       beam_path => maps:get(beam_path, Graph),
       sha256 => sha256_hex(maps:get(beam_path, Graph)),
       function_ids => [maps:get(id, Function)
                        || Function <- maps:get(functions, Graph)]}
     || Graph <- ModuleGraphs].

build_module_cfg(Beam, ModuleOrdinal) ->
    case beam_disasm:file(Beam) of
        {beam_file, Module, _Exports, _Attributes, CompileInfo, Functions} ->
            Built = [build_function_cfg(Module, Function, CompileInfo)
                     || Function <- Functions],
            #{module => Module,
              module_ordinal => ModuleOrdinal,
              beam_path => Beam,
              functions => lists:append([maps:get(functions, G) || G <- Built]),
              blocks => lists:append([maps:get(blocks, G) || G <- Built]),
              instructions => lists:append([maps:get(instructions, G) || G <- Built]),
              cfg_edges => lists:append([maps:get(cfg_edges, G) || G <- Built]),
              unsupported => lists:append([maps:get(unsupported, G) || G <- Built])};
        Other ->
            error({beam_disassembly_failed, Beam, Other})
    end.

merge_module_cfgs(ModuleGraphs) ->
    #{functions => lists:append([maps:get(functions, G) || G <- ModuleGraphs]),
      blocks => lists:append([maps:get(blocks, G) || G <- ModuleGraphs]),
      instructions => lists:append([maps:get(instructions, G) || G <- ModuleGraphs]),
      cfg_edges => lists:append([maps:get(cfg_edges, G) || G <- ModuleGraphs]),
      unsupported => lists:append([maps:get(unsupported, G) || G <- ModuleGraphs])}.

build_function_cfg(Module, {function, Name, Arity, Entry, RawInstructions}, CompileInfo) ->
    FunctionId = flow_function_id(Module, Name, Arity, Entry),
    RawBlocks = split_function_blocks(RawInstructions, Entry),
    Blocks0 = [materialize_block(FunctionId, B, CompileInfo) || B <- RawBlocks],
    LabelMap = maps:from_list(
      [{maps:get(label, B), maps:get(id, B)} || B <- Blocks0,
                                              is_integer(maps:get(label, B))]),
    EntryBlockId = case maps:find(Entry, LabelMap) of
        {ok, Id} -> Id;
        error -> error({function_entry_block_missing, FunctionId, Entry})
    end,
    Edges = build_cfg_edges(Blocks0, LabelMap),
    Function = #{id => FunctionId,
                 module => Module,
                 name => Name,
                 arity => Arity,
                 entry_label => Entry,
                 entry_block_id => EntryBlockId,
                 instruction_count => length(RawInstructions),
                 source => compile_source(CompileInfo)},
    #{functions => [Function],
      blocks => [maps:remove(instruction_records,
                             maps:remove(raw_instructions, B)) || B <- Blocks0],
      instructions => lists:append([maps:get(instruction_records, B) || B <- Blocks0]),
      cfg_edges => Edges,
      unsupported => unsupported_control_records(FunctionId, Blocks0, Edges)}.

flow_function_id(Module, Name, Arity, Entry) ->
    {function, Module, Name, Arity, Entry}.

flow_block_id(FunctionId, Label, Ordinal) ->
    {block, FunctionId, Label, Ordinal}.

flow_instruction_id(BlockId, Ordinal) ->
    {instruction, BlockId, Ordinal}.

flow_edge_id(BlockId, Ordinal) ->
    {cfg_edge, BlockId, Ordinal}.

split_function_blocks(Instructions, Entry) ->
    lists:reverse(split_blocks(Instructions, Entry, undefined, [], 1, [])).

split_blocks([], _Entry, _Label, [], _Ordinal, Acc) -> Acc;
split_blocks([], _Entry, Label, CurrentRev, Ordinal, Acc) ->
    [raw_block(Label, Ordinal, lists:reverse(CurrentRev)) | Acc];
split_blocks([{label, Label} = Instruction | Rest], Entry,
             _CurrentLabel, [], Ordinal, Acc) ->
    split_blocks(Rest, Entry, Label, [Instruction], Ordinal, Acc);
split_blocks([{label, Label} = Instruction | Rest], Entry,
             CurrentLabel, CurrentRev, Ordinal, Acc) ->
    Finished = raw_block(CurrentLabel, Ordinal, lists:reverse(CurrentRev)),
    split_blocks(Rest, Entry, Label, [Instruction], Ordinal + 1,
                 [Finished | Acc]);
split_blocks([Instruction | Rest], Entry, CurrentLabel0,
             CurrentRev, Ordinal, Acc) ->
    CurrentLabel = case CurrentLabel0 of
        undefined -> {synthetic, Entry, Ordinal};
        _ -> CurrentLabel0
    end,
    Updated = [Instruction | CurrentRev],
    case split_after_instruction(Instruction) of
        true ->
            Finished = raw_block(CurrentLabel, Ordinal,
                                 lists:reverse(Updated)),
            split_blocks(Rest, Entry, undefined, [], Ordinal + 1,
                         [Finished | Acc]);
        false ->
            split_blocks(Rest, Entry, CurrentLabel, Updated, Ordinal, Acc)
    end.

raw_block(Label, Ordinal, Instructions) ->
    #{label => Label, ordinal => Ordinal, raw_instructions => Instructions}.

split_after_instruction(return) -> true;
split_after_instruction({func_info, _, _, _}) -> true;
split_after_instruction({jump, _}) -> true;
split_after_instruction({'try', _, _}) -> true;
split_after_instruction({'catch', _, _}) -> true;
split_after_instruction({loop_rec, _, _}) -> true;
split_after_instruction({loop_rec_end, _}) -> true;
split_after_instruction({wait, _}) -> true;
split_after_instruction({wait_timeout, _, _}) -> true;
split_after_instruction({call_only, _, _}) -> true;
split_after_instruction({call_last, _, _, _}) -> true;
split_after_instruction({call_ext_only, _, _}) -> true;
split_after_instruction({call_ext_last, _, _, _}) -> true;
split_after_instruction({apply_last, _, _}) -> true;
split_after_instruction({select_val, _, _, _}) -> true;
split_after_instruction({select_tuple_arity, _, _, _}) -> true;
split_after_instruction(Instruction)
  when is_tuple(Instruction), tuple_size(Instruction) >= 1,
       element(1, Instruction) =:= test -> true;
split_after_instruction(Instruction) -> terminal_exception_instruction(Instruction).

terminal_exception_instruction({badmatch, _}) -> true;
terminal_exception_instruction({case_end, _}) -> true;
terminal_exception_instruction({if_end, _}) -> true;
terminal_exception_instruction({try_case_end, _}) -> true;
terminal_exception_instruction({raise, _, _}) -> true;
terminal_exception_instruction(_) -> false.

materialize_block(FunctionId,
                  #{label := Label, ordinal := Ordinal,
                    raw_instructions := RawInstructions}, CompileInfo) ->
    BlockId = flow_block_id(FunctionId, Label, Ordinal),
    InstructionRecords = materialize_instructions(
      RawInstructions, FunctionId, BlockId, Label, compile_source(CompileInfo)),
    InstructionIds = [maps:get(id, I) || I <- InstructionRecords],
    #{id => BlockId,
      function_id => FunctionId,
      label => Label,
      ordinal => Ordinal,
      instruction_count => length(InstructionRecords),
      instruction_ids => InstructionIds,
      instruction_records => InstructionRecords,
      raw_instructions => RawInstructions}.

materialize_instructions(Instructions, FunctionId, BlockId, Label, Source) ->
    materialize_instructions(Instructions, FunctionId, BlockId, Label,
                             Source, undefined, 1, []).

materialize_instructions([], _FunctionId, _BlockId, _Label, _Source,
                         _Line, _Ordinal, Acc) -> lists:reverse(Acc);
materialize_instructions([Instruction | Rest], FunctionId, BlockId, Label,
                         Source, Line0, Ordinal, Acc) ->
    Line = case Instruction of {line, Index} -> Index; _ -> Line0 end,
    Location = case Line of
        undefined -> #{source => Source, line_index => undefined};
        _ -> #{source => Source, line_index => Line}
    end,
    Record = #{id => flow_instruction_id(BlockId, Ordinal),
               function_id => FunctionId,
               block_id => BlockId,
               ordinal => Ordinal,
               current_label => Label,
               raw_instruction => Instruction,
               source_location => Location},
    materialize_instructions(Rest, FunctionId, BlockId, Label, Source,
                             Line, Ordinal + 1, [Record | Acc]).

compile_source(CompileInfo) ->
    case lists:keyfind(source, 1, CompileInfo) of
        {source, Source} -> Source;
        false -> undefined
    end.

build_cfg_edges(Blocks, LabelMap) ->
    build_cfg_edges(Blocks, LabelMap, []).

build_cfg_edges([], _LabelMap, Acc) -> lists:append(lists:reverse(Acc));
build_cfg_edges([Block], LabelMap, Acc) ->
    build_cfg_edges([], LabelMap,
                    [edges_for_block(Block, undefined, LabelMap) | Acc]);
build_cfg_edges([Block, Next | Rest], LabelMap, Acc) ->
    build_cfg_edges([Next | Rest], LabelMap,
                    [edges_for_block(Block, maps:get(id, Next), LabelMap) | Acc]).

edges_for_block(Block, NextBlockId, LabelMap) ->
    Raw = maps:get(raw_instructions, Block),
    Last = lists:last(Raw),
    Specs = edge_specs(Last, NextBlockId, LabelMap),
    SourceInstructionId = lists:last(maps:get(instruction_ids, Block)),
    [#{id => flow_edge_id(maps:get(id, Block), Ordinal),
       source_block_id => maps:get(id, Block),
       target_block_id => Target,
       source_instruction_id => SourceInstructionId,
       kind => Kind,
       predicate => Predicate,
       certainty => exact}
     || {{Kind, Target, Predicate}, Ordinal} <-
            lists:zip(Specs, lists:seq(1, length(Specs)))].

edge_specs(return, _Next, _Labels) -> [];
edge_specs({func_info, _, _, _}, _Next, _Labels) -> [];
edge_specs({call_only, _, _}, _Next, _Labels) -> [];
edge_specs({call_last, _, _, _}, _Next, _Labels) -> [];
edge_specs({call_ext_only, _, _}, _Next, _Labels) -> [];
edge_specs({call_ext_last, _, _, _}, _Next, _Labels) -> [];
edge_specs({apply_last, _, _}, _Next, _Labels) -> [];
edge_specs({badmatch, _}, _Next, _Labels) -> [];
edge_specs({case_end, _}, _Next, _Labels) -> [];
edge_specs({if_end, _}, _Next, _Labels) -> [];
edge_specs({try_case_end, _}, _Next, _Labels) -> [];
edge_specs({raise, _, _}, _Next, _Labels) -> [];
edge_specs({jump, Target}, _Next, Labels) ->
    target_edge(jump, Target, unconditional, Labels);
edge_specs({'try', _Register, Handler}, Next, Labels) ->
    target_edge(exception, Handler, protected_region, Labels) ++
    next_edge(try_body, Next, normal);
edge_specs({'catch', _Register, Handler}, Next, Labels) ->
    target_edge(exception, Handler, protected_region, Labels) ++
    next_edge(catch_body, Next, normal);
edge_specs({loop_rec, Empty, _Destination}, Next, Labels) ->
    target_edge(receive_wait, Empty, mailbox_empty, Labels) ++
    next_edge(message_match, Next, message_available);
edge_specs({loop_rec_end, Repeat}, _Next, Labels) ->
    target_edge(receive_wait, Repeat, scan_next_message, Labels);
edge_specs({wait, Repeat}, _Next, Labels) ->
    target_edge(receive_wait, Repeat, suspended, Labels);
edge_specs({wait_timeout, Repeat, Timeout}, Next, Labels) ->
    target_edge(receive_wait, Repeat, message_before_timeout, Labels) ++
    next_edge(timeout, Next, {timeout, Timeout});
edge_specs({select_val, Source, Default, Choices}, _Next, Labels) ->
    target_edge(selection_default, Default, {default, Source}, Labels) ++
    selection_edges(value, Source, Choices, Labels);
edge_specs({select_tuple_arity, Source, Default, Choices}, _Next, Labels) ->
    target_edge(selection_default, Default, {default, Source}, Labels) ++
    selection_edges(tuple_arity, Source, Choices, Labels);
edge_specs(Instruction, Next, Labels)
  when is_tuple(Instruction), tuple_size(Instruction) >= 3,
       element(1, Instruction) =:= test ->
    Test = element(2, Instruction),
    Fail = element(3, Instruction),
    target_edge(test_fail, Fail, {failed, Test}, Labels) ++
    next_edge(test_pass, Next, {passed, Test});
edge_specs(_Instruction, Next, _Labels) -> next_edge(fallthrough, Next, normal).

target_edge(_Kind, {f, 0}, _Predicate, _Labels) -> [];
target_edge(Kind, {f, Label}, Predicate, Labels) ->
    case maps:find(Label, Labels) of
        {ok, Target} -> [{Kind, Target, Predicate}];
        error -> error({missing_cfg_target_label, Label, Kind})
    end;
target_edge(Kind, Other, _Predicate, _Labels) ->
    error({invalid_cfg_target, Kind, Other}).

next_edge(_Kind, undefined, _Predicate) -> [];
next_edge(Kind, Target, Predicate) -> [{Kind, Target, Predicate}].

selection_edges(SelectionKind, Source, {list, Choices}, Labels) ->
    selection_edges(SelectionKind, Source, Choices, Labels);
selection_edges(SelectionKind, Source, Choices, Labels) when is_list(Choices) ->
    selection_pairs(SelectionKind, Source, Choices, Labels, []);
selection_edges(SelectionKind, Source, Other, _Labels) ->
    error({invalid_selection_choices, SelectionKind, Source, Other}).

selection_pairs(_Kind, _Source, [], _Labels, Acc) -> lists:reverse(Acc);
selection_pairs(Kind, Source, [Value, Target | Rest], Labels, Acc) ->
    Edge = target_edge(selection_case, Target, {Kind, Source, Value}, Labels),
    selection_pairs(Kind, Source, Rest, Labels, lists:reverse(Edge) ++ Acc);
selection_pairs(Kind, Source, Other, _Labels, _Acc) ->
    error({invalid_selection_pairs, Kind, Source, Other}).

unsupported_control_records(_FunctionId, _Blocks, _Edges) -> [].

validate_cfg(#{functions := Functions, blocks := Blocks,
               instructions := Instructions, cfg_edges := Edges} = Graph) ->
    ok = validate_unique_record_ids(Functions, function),
    ok = validate_unique_record_ids(Blocks, block),
    ok = validate_unique_record_ids(Instructions, instruction),
    ok = validate_unique_record_ids(Edges, cfg_edge),
    FunctionIds = [maps:get(id, F) || F <- Functions],
    BlockIds = [maps:get(id, B) || B <- Blocks],
    true = lists:all(fun(B) -> lists:member(maps:get(function_id, B), FunctionIds) end,
                     Blocks),
    true = lists:all(fun(I) -> lists:member(maps:get(block_id, I), BlockIds) end,
                     Instructions),
    true = lists:all(fun(E) ->
        lists:member(maps:get(source_block_id, E), BlockIds) andalso
        lists:member(maps:get(target_block_id, E), BlockIds)
    end, Edges),
    true = lists:all(fun(F) ->
        lists:member(maps:get(entry_block_id, F), BlockIds) andalso
        maps:get(instruction_count, F) =:=
          length([I || I <- Instructions,
                       maps:get(function_id, I) =:= maps:get(id, F)])
    end, Functions),
    true = lists:sum([maps:get(instruction_count, F) || F <- Functions])
           =:= length(Instructions),
    Graph.

validate_unique_record_ids(Records, Family) ->
    Ids = [maps:get(id, Record) || Record <- Records],
    case length(Ids) =:= length(lists:usort(Ids)) of
        true -> ok;
        false -> error({duplicate_flow_ids, Family})
    end.

analyze_cfg(#{functions := Functions, blocks := Blocks,
              instructions := Instructions, cfg_edges := Edges}) ->
    Results = [analyze_function_cfg(Function, Blocks, Instructions, Edges)
               || Function <- Functions],
    {lists:append([maps:get(block_states, Result) || Result <- Results]),
     lists:append([maps:get(dynamic_calls, Result) || Result <- Results])}.

analyze_function_cfg(Function, AllBlocks, AllInstructions, AllEdges) ->
    FunctionId = maps:get(id, Function),
    Blocks = lists:sort(
      fun(A, B) -> maps:get(ordinal, A) < maps:get(ordinal, B) end,
      [B || B <- AllBlocks, maps:get(function_id, B) =:= FunctionId]),
    BlockIds = [maps:get(id, B) || B <- Blocks],
    InstructionsByBlock = maps:from_list(
      [{BlockId,
        lists:sort(fun(A, B) -> maps:get(ordinal, A) < maps:get(ordinal, B) end,
                   [I || I <- AllInstructions,
                         maps:get(block_id, I) =:= BlockId])}
       || BlockId <- BlockIds]),
    Successors = maps:from_list(
      [{BlockId,
        lists:usort([maps:get(target_block_id, Edge)
                     || Edge <- AllEdges,
                        maps:get(source_block_id, Edge) =:= BlockId])}
       || BlockId <- BlockIds]),
    EntryId = maps:get(entry_block_id, Function),
    EntryState = flow_entry_state(maps:get(arity, Function)),
    {InStates, OutStates, Updates} = flow_worklist(
      [EntryId], #{EntryId => EntryState}, #{}, #{EntryId => 1},
      InstructionsByBlock, Successors),
    BlockStates = [flow_block_state_record(B, InStates, OutStates, Updates)
                   || B <- Blocks],
    Calls = lists:append(
      [resolve_block_calls(FunctionId, maps:get(id, B),
                           maps:get(maps:get(id, B), InStates, flow_unreachable_state()),
                           maps:get(maps:get(id, B), InstructionsByBlock, []))
       || B <- Blocks, maps:is_key(maps:get(id, B), InStates)]),
    #{block_states => BlockStates, dynamic_calls => Calls}.

flow_entry_state(Arity) ->
    #{x => maps:from_list(
              [{Index, {unknown, {argument, Index}}}
               || Index <- lists:seq(0, erlang:max(Arity - 1, -1))]),
      y => #{}}.

flow_unreachable_state() -> #{x => #{}, y => #{}, unreachable => true}.

flow_worklist([], InStates, OutStates, Updates, _Instructions, _Successors) ->
    {InStates, OutStates, Updates};
flow_worklist([BlockId | Rest], InStates0, OutStates0, Updates0,
              Instructions, Successors) ->
    InState = maps:get(BlockId, InStates0),
    OutState = transfer_block(maps:get(BlockId, Instructions, []), InState),
    OutStates = OutStates0#{BlockId => OutState},
    {InStates, Queue, Updates} = lists:foldl(
      fun(Successor, {InAcc, QueueAcc, UpdateAcc}) ->
          Old = maps:get(Successor, InAcc, undefined),
          Joined = case Old of
              undefined -> OutState;
              _ -> join_state(Old, OutState)
          end,
          case Old =:= Joined of
              true -> {InAcc, QueueAcc, UpdateAcc};
              false ->
                  Count = maps:get(Successor, UpdateAcc, 0) + 1,
                  Widened = case Count > 64 of
                      true -> widen_state(Old, Joined);
                      false -> Joined
                  end,
                  {InAcc#{Successor => Widened},
                   enqueue_block(Successor, QueueAcc),
                   UpdateAcc#{Successor => Count}}
          end
      end, {InStates0, Rest, Updates0}, maps:get(BlockId, Successors, [])),
    flow_worklist(Queue, InStates, OutStates, Updates,
                  Instructions, Successors).

enqueue_block(BlockId, Queue) ->
    case lists:member(BlockId, Queue) of true -> Queue; false -> Queue ++ [BlockId] end.

flow_block_state_record(Block, InStates, OutStates, Updates) ->
    BlockId = maps:get(id, Block),
    In = maps:get(BlockId, InStates, flow_unreachable_state()),
    Out = maps:get(BlockId, OutStates, flow_unreachable_state()),
    #{block_id => BlockId,
      function_id => maps:get(function_id, Block),
      state_in => In,
      state_out => Out,
      update_count => maps:get(BlockId, Updates, 0),
      widened => maps:get(BlockId, Updates, 0) > 64,
      reachable => maps:is_key(BlockId, InStates)}.

transfer_block(Instructions, State) ->
    lists:foldl(fun(Instruction, Current) ->
        transfer_instruction(maps:get(raw_instruction, Instruction), Current)
    end, State, Instructions).

transfer_instruction({move, Source, Destination}, State) ->
    flow_put_reg(Destination, flow_operand(Source, State), State);
transfer_instruction({swap, Left, Right}, State) ->
    LeftValue = flow_operand(Left, State),
    RightValue = flow_operand(Right, State),
    flow_put_reg(Right, LeftValue,
                 flow_put_reg(Left, RightValue, State));
transfer_instruction({put_list, Head, Tail, Destination}, State) ->
    flow_put_reg(Destination,
                 {list, [flow_operand(Head, State)], flow_operand(Tail, State)},
                 State);
transfer_instruction({put_tuple2, Destination, {list, Elements}}, State) ->
    flow_put_reg(Destination,
                 {tuple, length(Elements),
                  [flow_operand(Element, State) || Element <- Elements]},
                 State);
transfer_instruction({get_tuple_element, Source, Index, Destination}, State) ->
    Value = case flow_operand(Source, State) of
        {tuple, _Arity, Elements} when Index < length(Elements) ->
            lists:nth(Index + 1, Elements);
        _ -> {unknown, {tuple_element, Index}}
    end,
    flow_put_reg(Destination, Value, State);
transfer_instruction({get_list, Source, HeadDestination, TailDestination}, State) ->
    case flow_operand(Source, State) of
        {list, [Head | Rest], Tail} ->
            TailValue = case Rest of [] -> Tail; _ -> {list, Rest, Tail} end,
            flow_put_reg(TailDestination, TailValue,
                         flow_put_reg(HeadDestination, Head, State));
        _ ->
            flow_put_reg(TailDestination, {unknown, list_tail},
                         flow_put_reg(HeadDestination, {unknown, list_head}, State))
    end;
transfer_instruction({kill, Register}, State) -> flow_remove_reg(Register, State);
transfer_instruction({init_yregs, {list, Registers}}, State) ->
    lists:foldl(fun(Register, Acc) ->
        flow_put_reg(Register, {unknown, uninitialized}, Acc)
    end, State, Registers);
transfer_instruction({bif, Name, _Fail, _Arguments, Destination}, State) ->
    flow_put_reg(Destination, {unknown, {bif_result, Name}}, State);
transfer_instruction({gc_bif, Name, _Fail, _Live, _Arguments, Destination}, State) ->
    flow_put_reg(Destination, {unknown, {bif_result, Name}}, State);
transfer_instruction({make_fun3, Target, _Index, _Uniq, Destination}, State) ->
    flow_put_reg(Destination, flow_fun_target(Target), State);
transfer_instruction({make_fun2, Target, _Index, _Uniq, _Free}, State) ->
    flow_put_reg({x, 0}, flow_fun_target(Target), State);
transfer_instruction({call, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_ext, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_fun, _}, State) -> flow_call_result(State);
transfer_instruction({call_fun2, _, _, _}, State) -> flow_call_result(State);
transfer_instruction({apply, _}, State) -> flow_call_result(State);
transfer_instruction({apply_last, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_only, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_last, _, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_ext_only, _, _}, State) -> flow_call_result(State);
transfer_instruction({call_ext_last, _, _, _}, State) -> flow_call_result(State);
transfer_instruction({'try', Register, _}, State) ->
    flow_put_reg(Register, {unknown, try_tag}, State);
transfer_instruction({'catch', Register, _}, State) ->
    flow_put_reg(Register, {unknown, catch_tag}, State);
transfer_instruction({try_end, Register}, State) -> flow_remove_reg(Register, State);
transfer_instruction({catch_end, Register}, State) -> flow_remove_reg(Register, State);
transfer_instruction({try_case, Register}, State) -> flow_remove_reg(Register, State);
transfer_instruction(Instruction, State) ->
    case flow_no_effect_instruction(Instruction) of
        true -> State;
        false -> flow_unknown_effect(State, Instruction)
    end.

flow_no_effect_instruction(Instruction) when is_atom(Instruction) ->
    lists:member(Instruction, [return, remove_message, timeout]);
flow_no_effect_instruction(Instruction) when is_tuple(Instruction) ->
    lists:member(element(1, Instruction),
                 [label, line, func_info, test, test_heap, allocate,
                  allocate_heap, allocate_zero, allocate_heap_zero,
                  deallocate, trim, jump, select_val, select_tuple_arity,
                  loop_rec, loop_rec_end, wait, wait_timeout]);
flow_no_effect_instruction(_) -> false.

flow_unknown_effect(State, Instruction) ->
    State#{x => #{0 => {unknown, {unsupported_instruction, Instruction}}},
           y => #{}}.

flow_call_result(State) ->
    State#{x => #{0 => {unknown, call_result}}}.

flow_fun_target({Module, Name, Arity})
  when is_atom(Module), is_atom(Name), is_integer(Arity) ->
    {fun_target, Module, Name, Arity};
flow_fun_target({f, Label}) -> {unknown, {local_fun_label, Label}};
flow_fun_target(Other) -> {unknown, {fun_target, Other}}.

flow_operand({tr, Operand, _Type}, State) -> flow_operand(Operand, State);
flow_operand({x, Index}, State) -> maps:get(Index, maps:get(x, State, #{}),
                                           {unknown, {x, Index}});
flow_operand({y, Index}, State) -> maps:get(Index, maps:get(y, State, #{}),
                                           {unknown, {y, Index}});
flow_operand({atom, Value}, _State) -> {literal, Value};
flow_operand({integer, Value}, _State) -> {literal, Value};
flow_operand({float, Value}, _State) -> {literal, Value};
flow_operand({literal, Value}, _State) -> {literal, Value};
flow_operand(nil, _State) -> {literal, []};
flow_operand(Value, _State) when is_atom(Value); is_integer(Value);
                                 is_float(Value); is_binary(Value) ->
    {literal, Value};
flow_operand(Other, _State) -> {unknown, {operand, Other}}.

flow_put_reg({x, Index}, Value, State) ->
    X = maps:get(x, State, #{}),
    State#{x => X#{Index => Value}};
flow_put_reg({y, Index}, Value, State) ->
    Y = maps:get(y, State, #{}),
    State#{y => Y#{Index => Value}};
flow_put_reg(_Other, _Value, State) -> State.

flow_remove_reg({x, Index}, State) ->
    State#{x => maps:remove(Index, maps:get(x, State, #{}))};
flow_remove_reg({y, Index}, State) ->
    State#{y => maps:remove(Index, maps:get(y, State, #{}))};
flow_remove_reg(_Other, State) -> State.

join_state(Left, Right) ->
    #{x => join_register_maps(maps:get(x, Left, #{}), maps:get(x, Right, #{})),
      y => join_register_maps(maps:get(y, Left, #{}), maps:get(y, Right, #{}))}.

join_register_maps(Left, Right) ->
    Keys = lists:usort(maps:keys(Left) ++ maps:keys(Right)),
    maps:from_list([{Key, join_register_value(maps:find(Key, Left),
                                              maps:find(Key, Right))}
                    || Key <- Keys]).

join_register_value(error, _Right) -> {unknown, absent_on_path};
join_register_value(_Left, error) -> {unknown, absent_on_path};
join_register_value({ok, Value}, {ok, Value}) -> Value;
join_register_value({ok, {unknown, Reason}}, _Right) -> {unknown, Reason};
join_register_value(_Left, {ok, {unknown, Reason}}) -> {unknown, Reason};
join_register_value({ok, Left}, {ok, Right}) -> bounded_union([Left, Right]).

bounded_union(Values) ->
    Flat = lists:append([case V of {union, Members} -> Members; _ -> [V] end
                         || V <- Values]),
    Unique = lists:usort(Flat),
    case length(Unique) of
        1 -> hd(Unique);
        Count when Count =< 16 -> {union, Unique};
        _ -> {unknown, union_widened}
    end.

widen_state(_Old, New) ->
    #{x => maps:map(fun(_Key, _Value) -> {unknown, widened} end,
                    maps:get(x, New, #{})),
      y => maps:map(fun(_Key, _Value) -> {unknown, widened} end,
                    maps:get(y, New, #{}))}.

resolve_block_calls(FunctionId, BlockId, State0, Instructions) ->
    {CallsRev, _State} = lists:foldl(
      fun(Instruction, {Calls, State}) ->
          Raw = maps:get(raw_instruction, Instruction),
          NewCalls = case resolve_dynamic_call(Raw, State) of
              none -> Calls;
              Resolution ->
                  [#{callsite_id => {callsite, maps:get(id, Instruction)},
                     caller => FunctionId,
                     block_id => BlockId,
                     instruction_id => maps:get(id, Instruction),
                     instruction => Raw,
                     resolution => Resolution} | Calls]
          end,
          {NewCalls, transfer_instruction(Raw, State)}
      end, {[], State0}, Instructions),
    lists:reverse(CallsRev).

resolve_dynamic_call({apply, Arity}, State) when is_integer(Arity), Arity >= 0 ->
    classify_mfa(flow_operand({x, Arity}, State),
                 flow_operand({x, Arity + 1}, State), Arity);
resolve_dynamic_call({apply_last, Arity, _Deallocate}, State)
  when is_integer(Arity), Arity >= 0 ->
    classify_mfa(flow_operand({x, Arity}, State),
                 flow_operand({x, Arity + 1}, State), Arity);
resolve_dynamic_call({call_ext, 3, {extfunc, erlang, apply, 3}}, State) ->
    classify_mfa(flow_operand({x, 0}, State), flow_operand({x, 1}, State),
                 flow_list_arity(flow_operand({x, 2}, State)));
resolve_dynamic_call({call_ext_only, 3, {extfunc, erlang, apply, 3}}, State) ->
    classify_mfa(flow_operand({x, 0}, State), flow_operand({x, 1}, State),
                 flow_list_arity(flow_operand({x, 2}, State)));
resolve_dynamic_call({call_ext_last, 3, {extfunc, erlang, apply, 3}, _}, State) ->
    classify_mfa(flow_operand({x, 0}, State), flow_operand({x, 1}, State),
                 flow_list_arity(flow_operand({x, 2}, State)));
resolve_dynamic_call({call_fun, Arity}, State) ->
    classify_fun(flow_operand({x, Arity}, State), Arity);
resolve_dynamic_call({call_fun2, _Fail, Arity, _FunInfo}, State) ->
    classify_fun(flow_operand({x, Arity}, State), Arity);
resolve_dynamic_call(_Instruction, _State) -> none.

flow_list_arity({literal, List}) when is_list(List) -> length(List);
flow_list_arity({list, Elements, Tail}) ->
    case flow_list_arity(Tail) of
        unknown -> unknown;
        TailLength -> length(Elements) + TailLength
    end;
flow_list_arity({union, Values}) ->
    Lengths = lists:usort([flow_list_arity(Value) || Value <- Values]),
    case Lengths of [Length] -> Length; _ -> unknown end;
flow_list_arity(_) -> unknown.

classify_mfa(ModuleValue, FunctionValue, Arity) ->
    Modules = literal_atom_values(ModuleValue),
    Functions = literal_atom_values(FunctionValue),
    case {Modules, Functions, Arity} of
        {[Module], [Function], KnownArity} when is_integer(KnownArity) ->
            #{certainty => exact,
              target => {Module, Function, KnownArity}};
        {KnownModules, KnownFunctions, KnownArity}
          when is_list(KnownModules), KnownModules =/= [],
               is_list(KnownFunctions), KnownFunctions =/= [],
               is_integer(KnownArity) ->
            Targets = lists:usort(
              [{Module, Function, KnownArity}
               || Module <- KnownModules, Function <- KnownFunctions]),
            #{certainty => possible, targets => Targets};
        _ -> classify_partial_mfa(Modules, Functions, Arity)
    end.

classify_partial_mfa(Modules, Functions, Arity) ->
    Available0 = case Modules of
        [Module] -> #{module => Module};
        Values when is_list(Values), Values =/= [] -> #{possible_modules => Values};
        _ -> #{}
    end,
    Available1 = case Functions of
        [Function] -> Available0#{function => Function};
        Values2 when is_list(Values2), Values2 =/= [] ->
            Available0#{possible_functions => Values2};
        _ -> Available0
    end,
    Available = case Arity of
        Value when is_integer(Value) -> Available1#{argument_arity => Value};
        _ -> Available1
    end,
    case map_size(Available) of
        0 -> #{certainty => unresolved,
               reason => module_function_and_arguments_runtime_values};
        _ -> #{certainty => partial,
               reason => incomplete_mfa,
               available => Available}
    end.

literal_atom_values({literal, Value}) when is_atom(Value) -> [Value];
literal_atom_values({union, Values}) ->
    AtomSets = [literal_atom_values(Value) || Value <- Values],
    case lists:any(fun(Value) -> Value =:= unknown end, AtomSets) of
        true -> unknown;
        false -> lists:usort(lists:append(AtomSets))
    end;
literal_atom_values(_) -> unknown.

classify_fun({fun_target, Module, Function, Arity}, Arity) ->
    #{certainty => exact, target => {Module, Function, Arity}};
classify_fun({union, Values}, CallArity) ->
    Targets = lists:usort(
      [{Module, Function, TargetArity}
       || {fun_target, Module, Function, TargetArity} <- Values,
          TargetArity =:= CallArity]),
    case {Targets, length(Targets) =:= length(Values)} of
        {[_], true} -> #{certainty => exact, target => hd(Targets)};
        {[_ | _], true} -> #{certainty => possible, targets => Targets};
        _ -> #{certainty => unresolved, reason => fun_target_runtime_value}
    end;
classify_fun(_Value, Arity) ->
    #{certainty => unresolved,
      reason => fun_target_runtime_value,
      available => #{argument_arity => Arity}}.

build_callgraph(#{functions := Functions,
                  instructions := Instructions}, DynamicCalls, _Modules) ->
    DynamicIndex = maps:from_list(
      [{maps:get(instruction_id, Call), Call} || Call <- DynamicCalls]),
    Callsites = [Callsite
                 || Instruction <- Instructions,
                    Callsite <- callsite_for_instruction(
                      Instruction, Functions, DynamicIndex)],
    FunctionIndex = maps:from_list(
      [{flow_function_mfa(Function), maps:get(id, Function)}
       || Function <- Functions]),
    CallEdges = lists:append(
      [call_edges_for_callsite(Callsite, FunctionIndex)
       || Callsite <- Callsites]),
    Unresolved = [#{id => {unresolved_call, maps:get(id, Callsite)},
                    callsite_id => maps:get(id, Callsite),
                    caller_id => maps:get(caller_id, Callsite),
                    instruction_id => maps:get(instruction_id, Callsite),
                    resolution => maps:get(resolution, Callsite)}
                  || Callsite <- Callsites,
                     lists:member(
                       maps:get(certainty, maps:get(resolution, Callsite)),
                       [partial, unresolved])],
    {Callsites, CallEdges, Unresolved}.

callsite_for_instruction(Instruction, Functions, DynamicIndex) ->
    InstructionId = maps:get(id, Instruction),
    CallerId = maps:get(function_id, Instruction),
    Caller = function_by_id(CallerId, Functions),
    CallerMFA = flow_function_mfa(Caller),
    case maps:find(InstructionId, DynamicIndex) of
        {ok, Dynamic} ->
            [#{id => {callsite, InstructionId},
               caller_id => CallerId,
               caller_mfa => CallerMFA,
               instruction_id => InstructionId,
               kind => dynamic,
               raw_instruction => maps:get(raw_instruction, Instruction),
               resolution => maps:get(resolution, Dynamic)}];
        error ->
            case static_call_resolution(maps:get(raw_instruction, Instruction),
                                        CallerMFA, Functions) of
                none -> [];
                {Kind, TargetMFA} ->
                    [#{id => {callsite, InstructionId},
                       caller_id => CallerId,
                       caller_mfa => CallerMFA,
                       instruction_id => InstructionId,
                       kind => Kind,
                       raw_instruction => maps:get(raw_instruction, Instruction),
                       resolution => #{certainty => exact,
                                       target => TargetMFA}}]
            end
    end.

function_by_id(FunctionId, Functions) ->
    case [Function || Function <- Functions,
                      maps:get(id, Function) =:= FunctionId] of
        [Function] -> Function;
        [] -> error({callsite_caller_missing, FunctionId});
        _ -> error({duplicate_callsite_caller, FunctionId})
    end.

flow_function_mfa(Function) ->
    {maps:get(module, Function), maps:get(name, Function), maps:get(arity, Function)}.

static_call_resolution({call, _Arity, Target}, Caller, Functions) ->
    {local, normalize_static_target(Target, Caller, Functions)};
static_call_resolution({call_only, _Arity, Target}, Caller, Functions) ->
    {local_tail, normalize_static_target(Target, Caller, Functions)};
static_call_resolution({call_last, _Arity, Target, _Deallocate}, Caller, Functions) ->
    {local_tail, normalize_static_target(Target, Caller, Functions)};
static_call_resolution({call_ext, _Arity, {extfunc, M, F, A}}, _Caller, _Functions) ->
    {external, {M, F, A}};
static_call_resolution({call_ext_only, _Arity, {extfunc, M, F, A}}, _Caller, _Functions) ->
    {external_tail, {M, F, A}};
static_call_resolution({call_ext_last, _Arity, {extfunc, M, F, A}, _},
                       _Caller, _Functions) ->
    {external_tail, {M, F, A}};
static_call_resolution({bif, Name, _Fail, Arguments, _Destination},
                       _Caller, _Functions) ->
    {bif, {erlang, Name, length(Arguments)}};
static_call_resolution({gc_bif, Name, _Fail, _Live, Arguments, _Destination},
                       _Caller, _Functions) ->
    {bif, {erlang, Name, length(Arguments)}};
static_call_resolution(_Instruction, _Caller, _Functions) -> none.

normalize_static_target({Module, Function, Arity}, _Caller, _Functions)
  when is_atom(Module), is_atom(Function), is_integer(Arity) ->
    {Module, Function, Arity};
normalize_static_target({f, Label}, {Module, _Name, _Arity}, Functions) ->
    case [flow_function_mfa(Function)
          || Function <- Functions,
             maps:get(module, Function) =:= Module,
             maps:get(entry_label, Function) =:= Label] of
        [MFA] -> MFA;
        [] -> error({missing_local_call_target, Module, Label});
        _ -> error({duplicate_local_call_target, Module, Label})
    end;
normalize_static_target(Other, Caller, _Functions) ->
    error({invalid_static_call_target, Caller, Other}).

call_edges_for_callsite(Callsite, FunctionIndex) ->
    Resolution = maps:get(resolution, Callsite),
    case maps:get(certainty, Resolution) of
        exact ->
            [call_edge(Callsite, maps:get(target, Resolution), exact,
                       FunctionIndex, 1)];
        possible ->
            Targets = maps:get(targets, Resolution),
            [call_edge(Callsite, Target, possible, FunctionIndex, Ordinal)
             || {Target, Ordinal} <- lists:zip(Targets,
                                               lists:seq(1, length(Targets)))];
        partial -> [unresolved_call_edge(Callsite, partial)];
        unresolved -> [unresolved_call_edge(Callsite, unresolved)]
    end.

call_edge(Callsite, TargetMFA, Certainty, FunctionIndex, Ordinal) ->
    {TargetKind, TargetId} = case maps:find(TargetMFA, FunctionIndex) of
        {ok, FunctionId} -> {internal, FunctionId};
        error -> {external, external_node_id(TargetMFA)}
    end,
    #{id => {call_edge, maps:get(id, Callsite), Ordinal, TargetId},
      callsite_id => maps:get(id, Callsite),
      caller_id => maps:get(caller_id, Callsite),
      caller_mfa => maps:get(caller_mfa, Callsite),
      target_id => TargetId,
      target_mfa => TargetMFA,
      target_kind => TargetKind,
      kind => maps:get(kind, Callsite),
      certainty => Certainty,
      instruction_id => maps:get(instruction_id, Callsite)}.

unresolved_call_edge(Callsite, Certainty) ->
    TargetId = {unresolved, maps:get(id, Callsite)},
    #{id => {call_edge, maps:get(id, Callsite), 1, TargetId},
      callsite_id => maps:get(id, Callsite),
      caller_id => maps:get(caller_id, Callsite),
      caller_mfa => maps:get(caller_mfa, Callsite),
      target_id => TargetId,
      target_mfa => undefined,
      target_kind => unresolved,
      kind => maps:get(kind, Callsite),
      certainty => Certainty,
      instruction_id => maps:get(instruction_id, Callsite)}.

external_node_id({Module, Function, Arity}) ->
    {external, Module, Function, Arity}.

strong_components(Functions, CallEdges) ->
    Graph = digraph:new(),
    try
        FunctionIds = [maps:get(id, Function) || Function <- Functions],
        [digraph:add_vertex(Graph, FunctionId) || FunctionId <- FunctionIds],
        Internal = [Edge || Edge <- CallEdges,
                            maps:get(target_kind, Edge) =:= internal],
        [digraph:add_edge(Graph, maps:get(id, Edge),
                          maps:get(caller_id, Edge), maps:get(target_id, Edge), [])
         || Edge <- Internal],
        Components = digraph_utils:strong_components(Graph),
        lists:sort([lists:sort(Component) || Component <- Components])
    after
        true = digraph:delete(Graph)
    end.

validate_flow_ir(#{counts := Counts} = IR) ->
    Families = [{modules, modules},
                {functions, functions},
                {blocks, blocks},
                {instructions, instructions},
                {cfg_edges, cfg_edges},
                {block_states, block_states},
                {callsites, callsites},
                {call_edges, call_edges},
                {unresolved, unresolved},
                {unsupported, unsupported}],
    true = lists:all(fun({CountKey, IRKey}) ->
        maps:get(CountKey, Counts) =:= length(maps:get(IRKey, IR))
    end, Families),
    FunctionIds = [maps:get(id, Function) || Function <- maps:get(functions, IR)],
    true = lists:all(fun(Edge) ->
        lists:member(maps:get(caller_id, Edge), FunctionIds) andalso
        case maps:get(target_kind, Edge) of
            internal -> lists:member(maps:get(target_id, Edge), FunctionIds);
            external -> true;
            unresolved -> true
        end
    end, maps:get(call_edges, IR)),
    IR.

write_json(Path, Term) ->
    Json = iolist_to_binary(json:encode(json_safe(Term))),
    write_binary_exclusive(Path, <<Json/binary, "\n">>).

json_safe(Value) when is_integer(Value); is_float(Value) -> Value;
json_safe(Value) when is_binary(Value) ->
    case unicode:characters_to_binary(Value, utf8, utf8) of
        Value -> Value;
        _ -> #{<<"erlang_binary_base64">> => base64:encode(Value)}
    end;
json_safe(true) -> true;
json_safe(false) -> false;
json_safe(null) -> null;
json_safe(undefined) -> null;
json_safe(Value) when is_atom(Value) -> atom_to_binary(Value, utf8);
json_safe([]) -> [];
json_safe(Value) when is_list(Value) ->
    case printable_unicode_list(Value) of
        true -> unicode:characters_to_binary(Value);
        false -> [json_safe(Element) || Element <- Value]
    end;
json_safe(Value) when is_map(Value) ->
    Pairs = lists:sort(
      [{json_key(Key), json_safe(Element)}
       || {Key, Element} <- maps:to_list(Value)]),
    maps:from_list(Pairs);
json_safe(Value) ->
    #{<<"erlang_term">> => unicode:characters_to_binary(
                              io_lib:format("~tp", [Value])),
      <<"etf_base64">> => base64:encode(term_to_binary(Value))}.

printable_unicode_list(Value) ->
    try io_lib:printable_unicode_list(Value)
    catch _:_ -> false
    end.

json_key(Key) when is_binary(Key) -> Key;
json_key(Key) when is_atom(Key) -> atom_to_binary(Key, utf8);
json_key(Key) when is_integer(Key) -> integer_to_binary(Key);
json_key(Key) -> unicode:characters_to_binary(io_lib:format("~tp", [Key])).

write_callgraph_dot(Path, IR) ->
    Functions = maps:get(functions, IR),
    Edges = maps:get(call_edges, IR),
    {AllIds, Index} = graph_node_index(Functions, Edges),
    FunctionIds = [maps:get(id, Function) || Function <- Functions],
    Nodes = [case lists:member(Id, FunctionIds) of
                 true -> dot_function_node(Id, Functions, Index);
                 false -> dot_nonfunction_node(Id, Edges, Index)
             end || Id <- AllIds],
    EdgeLines = [dot_call_edge(Edge, Index) || Edge <- Edges],
    write_binary_exclusive(Path,
      ["digraph beam_flow {\n",
       "  rankdir=LR;\n  graph [charset=\"UTF-8\"];\n",
       Nodes, EdgeLines, "}\n"]).

graph_node_index(Functions, Edges) ->
    FunctionIds = [maps:get(id, Function) || Function <- Functions],
    OtherIds = lists:usort(
      [maps:get(target_id, Edge) || Edge <- Edges,
                                   maps:get(target_kind, Edge) =/= internal]),
    AllIds = FunctionIds ++ OtherIds,
    {AllIds, maps:from_list(
               [{Id, "n" ++ integer_to_list(Ordinal)}
                || {Id, Ordinal} <- lists:zip(AllIds,
                                              lists:seq(1, length(AllIds)))])}.

dot_function_node(Id, Functions, Index) ->
    [Function] = [Candidate || Candidate <- Functions,
                               maps:get(id, Candidate) =:= Id],
    Label = mfa_text(flow_function_mfa(Function)),
    io_lib:format("  ~s [shape=box,label=\"~s\"];~n",
                  [maps:get(Id, Index), dot_escape(Label)]).

dot_nonfunction_node(Id, Edges, Index) ->
    Matching = [Edge || Edge <- Edges, maps:get(target_id, Edge) =:= Id],
    Label = case Matching of
        [Edge | _] -> case maps:get(target_mfa, Edge, undefined) of
            undefined -> flow_text(Id);
            MFA -> mfa_text(MFA)
        end;
        [] -> flow_text(Id)
    end,
    Shape = case Id of {unresolved, _} -> "diamond"; _ -> "ellipse" end,
    io_lib:format("  ~s [shape=~s,label=\"~s\"];~n",
                  [maps:get(Id, Index), Shape, dot_escape(Label)]).

dot_call_edge(Edge, Index) ->
    Label = io_lib:format("~p/~p", [maps:get(kind, Edge),
                                     maps:get(certainty, Edge)]),
    io_lib:format("  ~s -> ~s [label=\"~s\"];~n",
                  [maps:get(maps:get(caller_id, Edge), Index),
                   maps:get(maps:get(target_id, Edge), Index),
                   dot_escape(lists:flatten(Label))]).

write_graphml(Path, IR) ->
    Functions = maps:get(functions, IR),
    Edges = maps:get(call_edges, IR),
    {AllIds, Index} = graph_node_index(Functions, Edges),
    FunctionIds = [maps:get(id, Function) || Function <- Functions],
    Nodes = [graphml_node(Id, FunctionIds, Functions, Edges, Index)
             || Id <- AllIds],
    EdgeLines = [graphml_edge(Edge, Ordinal, Index)
                 || {Edge, Ordinal} <- lists:zip(Edges,
                                                 lists:seq(1, length(Edges)))],
    write_binary_exclusive(Path,
      ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
       "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n",
       "<key id=\"label\" for=\"all\" attr.name=\"label\" attr.type=\"string\"/>\n",
       "<key id=\"kind\" for=\"edge\" attr.name=\"kind\" attr.type=\"string\"/>\n",
       "<key id=\"certainty\" for=\"edge\" attr.name=\"certainty\" attr.type=\"string\"/>\n",
       "<graph id=\"beam_flow\" edgedefault=\"directed\">\n",
       Nodes, EdgeLines, "</graph>\n</graphml>\n"]).

graphml_node(Id, FunctionIds, Functions, Edges, Index) ->
    Label = case lists:member(Id, FunctionIds) of
        true ->
            [Function] = [Candidate || Candidate <- Functions,
                                       maps:get(id, Candidate) =:= Id],
            mfa_text(flow_function_mfa(Function));
        false ->
            case [maps:get(target_mfa, Edge, undefined)
                  || Edge <- Edges, maps:get(target_id, Edge) =:= Id] of
                [undefined | _] -> flow_text(Id);
                [MFA | _] -> mfa_text(MFA);
                [] -> flow_text(Id)
            end
    end,
    io_lib:format("<node id=\"~s\"><data key=\"label\">~s</data></node>~n",
                  [maps:get(Id, Index), xml_escape(Label)]).

graphml_edge(Edge, Ordinal, Index) ->
    io_lib:format(
      "<edge id=\"e~B\" source=\"~s\" target=\"~s\"><data key=\"kind\">~s</data><data key=\"certainty\">~s</data></edge>~n",
      [Ordinal,
       maps:get(maps:get(caller_id, Edge), Index),
       maps:get(maps:get(target_id, Edge), Index),
       xml_escape(atom_to_list(maps:get(kind, Edge))),
       xml_escape(atom_to_list(maps:get(certainty, Edge)))]).

write_cfg_dots(Output, IR) ->
    CfgDirectory = filename:join(Output, "cfg"),
    ok = file:make_dir(CfgDirectory),
    Entries = [write_function_cfg_dot(CfgDirectory, Function, IR)
               || Function <- maps:get(functions, IR)],
    write_term_exclusive(filename:join(Output, "cfg-index.term"), Entries).

write_function_cfg_dot(CfgDirectory, Function, IR) ->
    FunctionId = maps:get(id, Function),
    Blocks = [Block || Block <- maps:get(blocks, IR),
                       maps:get(function_id, Block) =:= FunctionId],
    BlockIds = [maps:get(id, Block) || Block <- Blocks],
    Edges = [Edge || Edge <- maps:get(cfg_edges, IR),
                     lists:member(maps:get(source_block_id, Edge), BlockIds)],
    Index = maps:from_list(
      [{Id, "b" ++ integer_to_list(Ordinal)}
       || {Id, Ordinal} <- lists:zip(BlockIds,
                                     lists:seq(1, length(BlockIds)))]),
    Digest = lists:sublist(hex(crypto:hash(sha256,
                                          term_to_binary(FunctionId))), 16),
    DotName = Digest ++ ".dot",
    SvgName = Digest ++ ".svg",
    Path = filename:join(CfgDirectory, DotName),
    Nodes = [io_lib:format("  ~s [shape=box,label=\"~s\"];~n",
                           [maps:get(maps:get(id, Block), Index),
                            dot_escape(flow_text(
                              {maps:get(label, Block),
                               maps:get(ordinal, Block)}))])
             || Block <- Blocks],
    EdgeLines = [io_lib:format("  ~s -> ~s [label=\"~s\"];~n",
                               [maps:get(maps:get(source_block_id, Edge), Index),
                                maps:get(maps:get(target_block_id, Edge), Index),
                                dot_escape(atom_to_list(maps:get(kind, Edge)))])
                 || Edge <- Edges],
    write_binary_exclusive(Path,
      ["digraph beam_cfg {\n  rankdir=TB;\n", Nodes, EdgeLines, "}\n"]),
    #{function_id => FunctionId, dot => DotName, svg => SvgName}.

mfa_text({Module, Function, Arity}) ->
    lists:flatten(io_lib:format("~p:~p/~B", [Module, Function, Arity])).

flow_text(Term) -> lists:flatten(io_lib:format("~tp", [Term])).

dot_escape(Text) -> escape_characters(Text, dot).
xml_escape(Text) -> escape_characters(Text, xml).

escape_characters([], _Mode) -> [];
escape_characters([$\\ | Rest], dot) -> [$\\, $\\ | escape_characters(Rest, dot)];
escape_characters([$" | Rest], dot) -> [$\\, $" | escape_characters(Rest, dot)];
escape_characters([$\n | Rest], dot) -> [$\\, $n | escape_characters(Rest, dot)];
escape_characters([$& | Rest], xml) -> "&amp;" ++ escape_characters(Rest, xml);
escape_characters([$< | Rest], xml) -> "&lt;" ++ escape_characters(Rest, xml);
escape_characters([$> | Rest], xml) -> "&gt;" ++ escape_characters(Rest, xml);
escape_characters([$" | Rest], xml) -> "&quot;" ++ escape_characters(Rest, xml);
escape_characters([$' | Rest], xml) -> "&apos;" ++ escape_characters(Rest, xml);
escape_characters([Character | Rest], Mode) ->
    [Character | escape_characters(Rest, Mode)].

write_flow_html(Path, IR) ->
    Json0 = iolist_to_binary(json:encode(json_safe(IR))),
    Json = escape_script_json(Json0),
    Css =
      "<style>"
      ":root{color-scheme:dark;--bg:#111827;--panel:#1f2937;--line:#475569;--text:#e5e7eb;--muted:#94a3b8;--accent:#38bdf8;--observed:#34d399}"
      "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px ui-monospace,SFMono-Regular,Consolas,monospace}"
      "header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;gap:20px;align-items:center;flex-wrap:wrap}"
      "header h1{font:600 20px system-ui;margin:0}#counts{color:var(--muted)}"
      "nav{display:flex;gap:8px;padding:10px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}"
      "button,input{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:5px;padding:7px 10px}"
      "button.active{border-color:var(--accent);color:var(--accent)}input{min-width:280px;margin-left:auto}"
      "main{display:grid;grid-template-columns:minmax(320px,1fr) minmax(320px,2fr);min-height:calc(100vh - 110px)}"
      "#view{padding:16px;overflow:auto;border-right:1px solid var(--line)}#details{padding:16px;overflow:auto}"
      "table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #334155;padding:7px}"
      "tr.clickable:hover,.card:hover{background:#243244;cursor:pointer}.muted{color:var(--muted)}"
      ".flow{display:flex;flex-direction:column;gap:7px}.edge{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:center}"
      ".node,.card{border:1px solid var(--line);border-radius:5px;background:var(--panel);padding:8px}.arrow{color:var(--accent)}"
      "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1220;border:1px solid #334155;padding:10px;border-radius:5px}"
      "h2{font:600 17px system-ui}h3{font:600 14px system-ui;color:var(--accent)}"
      "</style>",
    Javascript =
      "<script>(()=>{'use strict';"
      "const data=JSON.parse(document.getElementById('beam-flow-data').textContent);"
      "const view=document.getElementById('view');const details=document.getElementById('details');const search=document.getElementById('search');"
      "const buttons=[...document.querySelectorAll('nav button')];let active='inventory';let selected=null;"
      "const key=v=>JSON.stringify(v);const text=v=>typeof v==='string'?v:JSON.stringify(v);"
      "const mfa=f=>f.module+':'+f.name+'/'+f.arity;const byId=new Map(data.functions.map(f=>[key(f.id),f]));"
      "function el(tag,content,cls){const n=document.createElement(tag);if(cls)n.className=cls;if(content!==undefined)n.textContent=String(content);return n}"
      "function clear(n){n.replaceChildren()}function heading(s){view.append(el('h2',s))}"
      "function showDetails(f){selected=f;clear(details);details.append(el('h2',mfa(f)));details.append(el('h3','Identity and location'));details.append(el('pre',JSON.stringify(f,null,2)));"
      "const blocks=data.blocks.filter(b=>key(b.function_id)===key(f.id));details.append(el('h3','Basic blocks ('+blocks.length+')'));"
      "for(const b of blocks){const c=el('div',undefined,'card');c.append(el('div','label '+text(b.label)+' / block '+b.ordinal));c.append(el('div',b.instruction_count+' instructions','muted'));c.onclick=()=>showBlock(f,b);details.append(c)}"
      "const calls=data.call_edges.filter(e=>key(e.caller_id)===key(f.id)||key(e.target_id)===key(f.id));details.append(el('h3','Dependencies ('+calls.length+')'));details.append(el('pre',JSON.stringify(calls,null,2)))}"
      "function showBlock(f,b){clear(details);details.append(el('h2',mfa(f)+' — block '+b.ordinal));const ins=data.instructions.filter(i=>key(i.block_id)===key(b.id));const edges=data.cfg_edges.filter(e=>key(e.source_block_id)===key(b.id));details.append(el('h3','Instructions'));details.append(el('pre',JSON.stringify(ins,null,2)));details.append(el('h3','Successors'));details.append(el('pre',JSON.stringify(edges,null,2)));const st=data.block_states.find(s=>key(s.block_id)===key(b.id));details.append(el('h3','Fixed-point state'));details.append(el('pre',JSON.stringify(st,null,2)))}"
      "function inventory(){clear(view);heading('Complete function inventory');const q=search.value.toLowerCase();const table=el('table');const head=el('tr');['Function','Entry','Instructions'].forEach(x=>head.append(el('th',x)));table.append(head);"
      "for(const f of data.functions){if(q&&!mfa(f).toLowerCase().includes(q))continue;const row=el('tr',undefined,'clickable');row.append(el('td',mfa(f)));row.append(el('td',f.entry_label));row.append(el('td',f.instruction_count));row.onclick=()=>showDetails(f);table.append(row)}view.append(table)}"
      "function callgraph(){clear(view);heading('Complete call-flow scheme');const flow=el('div',undefined,'flow');for(const e of data.call_edges){const row=el('div',undefined,'edge');const left=el('div',mfa({module:e.caller_mfa.erlang_term||text(e.caller_mfa),name:'',arity:''}),'node');left.textContent=text(e.caller_mfa);const arrow=el('div','→ '+e.kind+' / '+e.certainty,'arrow');const right=el('div',e.target_mfa===null?text(e.target_id):text(e.target_mfa),'node');row.append(left,arrow,right);flow.append(row)}view.append(flow)}"
      "function cfg(){clear(view);heading('Per-function control flow');const f=selected||data.functions[0];if(!f)return;const title=el('div','Selected: '+mfa(f),'card');title.onclick=()=>showDetails(f);view.append(title);const blocks=data.blocks.filter(b=>key(b.function_id)===key(f.id));for(const b of blocks){const card=el('div',undefined,'card');const outgoing=data.cfg_edges.filter(e=>key(e.source_block_id)===key(b.id));card.append(el('div','Block '+b.ordinal+' — '+text(b.label)));card.append(el('div',outgoing.map(e=>e.kind+' → '+text(e.target_block_id)).join(' | ')||'terminal','muted'));card.onclick=()=>showBlock(f,b);view.append(card)}}"
      "function records(title,rows){clear(view);heading(title);const pre=el('pre',JSON.stringify(rows,null,2));view.append(pre)}"
      "function render(){buttons.forEach(b=>b.classList.toggle('active',b.dataset.view===active));if(active==='inventory')inventory();else if(active==='calls')callgraph();else if(active==='cfg')cfg();else if(active==='dependencies')records('Complete callsites and dependencies',data.callsites);else if(active==='dynamic')records('Dynamic call resolution',data.dynamic_calls);else if(active==='unknowns')records('Unresolved and unsupported records',{unresolved:data.unresolved,unsupported:data.unsupported});else records('Runtime unavailable',data.runtime)}"
      "buttons.forEach(b=>b.onclick=()=>{active=b.dataset.view;render()});search.oninput=()=>{if(active!=='inventory')active='inventory';render()};"
      "document.getElementById('counts').textContent=Object.entries(data.counts).map(([k,v])=>k+'='+v).join(' · ');render();"
      "})();</script>",
    Html = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Erlang BEAM Flow Explorer</title>", Css,
            "</head><body><header><h1>Erlang BEAM Flow Explorer</h1><span id='counts'></span></header>",
            "<nav><button data-view='inventory'>Inventory</button><button data-view='calls'>Call flow</button>",
            "<button data-view='cfg'>CFG</button><button data-view='dependencies'>Dependencies</button>",
            "<button data-view='dynamic'>Dynamic calls</button><button data-view='unknowns'>Unknowns</button>",
            "<button data-view='runtime'>Runtime</button><input id='search' aria-label='Search functions' placeholder='Search complete function inventory'></nav>",
            "<main><section id='view'></section><aside id='details'><h2>Complete function inventory</h2><p class='muted'>Select a function to inspect blocks, instructions, dependencies, and abstract states.</p><p>Runtime unavailable</p></aside></main>",
            "<script id=\"beam-flow-data\" type=\"application/json\">", Json,
            "</script>", Javascript, "</body></html>"],
    write_binary_exclusive(Path, unicode:characters_to_binary(Html)).

escape_script_json(Binary) ->
    Replacements = [{<<"&">>, <<"\\u0026">>},
                    {<<"<">>, <<"\\u003c">>},
                    {<<">">>, <<"\\u003e">>},
                    {<<16#E2,16#80,16#A8>>, <<"\\u2028">>},
                    {<<16#E2,16#80,16#A9>>, <<"\\u2029">>}],
    lists:foldl(fun({Pattern, Replacement}, Acc) ->
        binary:replace(Acc, Pattern, Replacement, [global])
    end, Binary, Replacements).

flow_query(GraphDir, Origin, DirectionText, MaxDepthText, FormatText) ->
    true = filelib:is_regular(filename:join(GraphDir, ".beam-flow-ir")),
    Manifest = consult_one(filename:join(GraphDir, "flow-manifest.term")),
    beam_flow_ir_v1 = maps:get(schema, Manifest),
    complete = maps:get(state, Manifest),
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    IR = validate_flow_ir(IR),
    Direction = case DirectionText of
        "callers" -> callers;
        "callees" -> callees;
        "both" -> both;
        _ -> error({invalid_query_direction, DirectionText})
    end,
    MaxDepth = decimal_integer(MaxDepthText),
    true = MaxDepth >= 0,
    Format = case FormatText of
        "term" -> term;
        "json" -> json;
        _ -> error({invalid_query_format, FormatText})
    end,
    OriginId = resolve_query_origin(Origin, maps:get(functions, IR)),
    NodeDepths = bounded_graph_walk(OriginId, Direction, MaxDepth,
                                    maps:get(call_edges, IR)),
    NodeIds = maps:keys(NodeDepths),
    ViewFunctions = [Function || Function <- maps:get(functions, IR),
                                 lists:member(maps:get(id, Function), NodeIds)],
    ViewEdges = [Edge || Edge <- maps:get(call_edges, IR),
                         lists:member(maps:get(caller_id, Edge), NodeIds),
                         maps:get(target_kind, Edge) =:= internal,
                         lists:member(maps:get(target_id, Edge), NodeIds)],
    Result = #{schema => beam_flow_query_v1,
               state => complete,
               origin => OriginId,
               direction => Direction,
               max_depth => MaxDepth,
               format => Format,
               authoritative_graph_counts => maps:get(counts, Manifest),
               view_counts => #{functions => length(ViewFunctions),
                                call_edges => length(ViewEdges)},
               node_depths => NodeDepths,
               functions => ViewFunctions,
               call_edges => ViewEdges},
    case Format of
        term -> io:format("~tp.~n", [Result]);
        json -> io:put_chars([json:encode(json_safe(Result)), "\n"])
    end,
    ok.

resolve_query_origin(Origin, Functions) ->
    case re:run(Origin,
                "^([A-Za-z][A-Za-z0-9_@]*):([A-Za-z][A-Za-z0-9_@!?]*?)/([0-9]+)$",
                [{capture, [1, 2, 3], list}]) of
        {match, [ModuleText, FunctionText, ArityText]} ->
            MFA = {list_to_atom(ModuleText), list_to_atom(FunctionText),
                   decimal_integer(ArityText)},
            case [maps:get(id, Function) || Function <- Functions,
                                           flow_function_mfa(Function) =:= MFA] of
                [FunctionId] -> FunctionId;
                [] -> error({query_origin_not_found, MFA});
                _ -> error({query_origin_ambiguous, MFA})
            end;
        nomatch -> error({invalid_query_origin, Origin})
    end.

bounded_graph_walk(OriginId, Direction, MaxDepth, Edges) ->
    graph_walk_queue([{OriginId, 0}], #{OriginId => 0},
                     Direction, MaxDepth, Edges).

graph_walk_queue([], Visited, _Direction, _MaxDepth, _Edges) -> Visited;
graph_walk_queue([{Node, Depth} | Rest], Visited0, Direction, MaxDepth, Edges) ->
    case Depth >= MaxDepth of
        true -> graph_walk_queue(Rest, Visited0, Direction, MaxDepth, Edges);
        false ->
            Neighbors = query_neighbors(Node, Direction, Edges),
            {Visited, Queue} = lists:foldl(fun(Neighbor, {VAcc, QAcc}) ->
                case maps:is_key(Neighbor, VAcc) of
                    true -> {VAcc, QAcc};
                    false -> {VAcc#{Neighbor => Depth + 1},
                              QAcc ++ [{Neighbor, Depth + 1}]}
                end
            end, {Visited0, Rest}, Neighbors),
            graph_walk_queue(Queue, Visited, Direction, MaxDepth, Edges)
    end.

query_neighbors(Node, callers, Edges) ->
    lists:usort([maps:get(caller_id, Edge)
                 || Edge <- Edges,
                    maps:get(target_kind, Edge) =:= internal,
                    maps:get(target_id, Edge) =:= Node]);
query_neighbors(Node, callees, Edges) ->
    lists:usort([maps:get(target_id, Edge)
                 || Edge <- Edges,
                    maps:get(target_kind, Edge) =:= internal,
                    maps:get(caller_id, Edge) =:= Node]);
query_neighbors(Node, both, Edges) ->
    lists:usort(query_neighbors(Node, callers, Edges) ++
                query_neighbors(Node, callees, Edges)).

flow_live(Output, GraphDir, NodeText, CookiePath, BackendText,
          DurationText, MaxEventsText, MaxBytesText, AgentBeam,
          ControlPath, LegacyAuthorizedText, ProcessCountText,
          FunctionCountText, EventCountText, Selectors) ->
    ProcessCount = decimal_integer(ProcessCountText),
    FunctionCount = decimal_integer(FunctionCountText),
    EventCount = decimal_integer(EventCountText),
    true = ProcessCount >= 0 andalso FunctionCount >= 0 andalso EventCount >= 0,
    true = length(Selectors) =:= ProcessCount + FunctionCount + EventCount,
    {ProcessSelectors, Rest1} = lists:split(ProcessCount, Selectors),
    {FunctionSelectors, Rest2} = lists:split(FunctionCount, Rest1),
    {EventSelectors, []} = lists:split(EventCount, Rest2),
    Graph = consult_one(filename:join(GraphDir, "flow-ir.term")),
    beam_flow_ir_v1 = maps:get(schema, Graph),
    complete = maps:get(state, Graph),
    ModuleNames = [maps:get(module, Record)
                   || Record <- maps:get(modules, Graph)],
    GraphFunctions = maps:get(functions, Graph),
    FunctionPatterns = live_function_patterns(
      FunctionSelectors, ModuleNames, GraphFunctions),
    Duration = live_limit(DurationText),
    MaxEvents = live_limit(MaxEventsText),
    MaxBytes = live_limit(MaxBytesText),
    LegacyAuthorized = text_boolean(LegacyAuthorizedText),
    true = ((Duration =:= infinity andalso MaxEvents =:= infinity andalso
             MaxBytes =:= infinity) orelse
            (is_integer(Duration) andalso is_integer(MaxEvents) andalso
             is_integer(MaxBytes))),
    Target = start_live_controller(NodeText, CookiePath),
    Preflight = preflight_live_node(Target, ModuleNames),
    Backend = select_trace_backend(BackendText,
                                   maps:get(capabilities, Preflight),
                                   LegacyAuthorized),
    AgentBinary = read_binary(AgentBeam),
    {ok, {beam_flow_runtime_agent, [{exports, _}]}} =
        beam_lib:chunks(AgentBinary, [exports]),
    false = live_call(Target, code, is_loaded, [beam_flow_runtime_agent]),
    {module, beam_flow_runtime_agent} = live_call(
      Target, code, load_binary,
      [beam_flow_runtime_agent, AgentBeam, AgentBinary]),
    Limits = #{duration_ms => live_duration_ms(Duration),
               max_events => MaxEvents,
               max_bytes => MaxBytes},
    RunId = make_ref(),
    RunCaptured = run_live_controlled(
      Target, ModuleNames, ProcessSelectors, FunctionPatterns,
      EventSelectors, Limits, Backend, RunId, ControlPath),
    AgentCleanup = unload_live_agent(Target),
    RunOutcome = case RunCaptured of
        {ok, Result} -> Result;
        {error, Failure} -> error({live_trace_failed, Failure, AgentCleanup})
    end,
    beam_flow_runtime_result_v1 = maps:get(schema, RunOutcome),
    CodeBefore = maps:get(module_paths, Preflight),
    CodeAfter = live_module_paths(Target, ModuleNames),
    CodeUnchanged = CodeBefore =:= CodeAfter,
    true = CodeUnchanged,
    TargetResponsive = net_adm:ping(Target) =:= pong andalso
                       live_call(Target, erlang, node, []) =:= Target,
    true = TargetResponsive,
    Events = correlate_runtime_events(maps:get(events, RunOutcome)),
    TraceCleanup = maps:get(trace_cleanup, RunOutcome),
    TemporaryAgentUnloaded = maps:get(unloaded, AgentCleanup),
    State = case maps:get(state, RunOutcome) =:= complete andalso
                 CodeUnchanged andalso TemporaryAgentUnloaded andalso
                 TargetResponsive of
        true -> complete;
        false -> partial
    end,
    Capture = maps:get(capture, RunOutcome),
    RuntimeOverlay = write_runtime_artifacts(Output, Graph, Events, State),
    RuntimeCounts = maps:get(runtime_counts, RuntimeOverlay),
    Runtime = #{otp_release => maps:get(otp_release, Preflight),
                erts_version => maps:get(erts_version, Preflight),
                erl_path => getenv_required("BEAM_TOOLKIT_ERL_PATH"),
                erlc_path => getenv_required("BEAM_TOOLKIT_ERLC_PATH"),
                escript_path => getenv_required("BEAM_TOOLKIT_ESCRIPT_PATH")},
    Cleanup = TraceCleanup#{temporary_agent_unloaded =>
                                TemporaryAgentUnloaded,
                            temporary_agent_cleanup => AgentCleanup,
                            target_responsive_after => TargetResponsive},
    Manifest = #{schema => beam_flow_trace_v1,
                 version => 1,
                 state => State,
                 mode => live_runtime,
                 node => Target,
                 controller_node => node(),
                 runtime => Runtime,
                 trace_backend => Backend,
                 bounds => Limits,
                 instrumentation => #{process_selectors => ProcessSelectors,
                                      function_patterns => FunctionPatterns,
                                      event_selectors => EventSelectors,
                                      arming => maps:get(arming, Capture)},
                 preflight => Preflight,
                 capture => Capture,
                 code_identity => #{before => CodeBefore,
                                    'after' => CodeAfter,
                                    unchanged => CodeUnchanged},
                 on_load => maps:get(on_load, RunOutcome),
                 cleanup => Cleanup,
                 runtime_overlay => #{schema => maps:get(schema,
                                                         RuntimeOverlay),
                                      counts => RuntimeCounts},
                 counts => maps:merge(
                   #{events => length(Events),
                     raw_frames => length(Events),
                     normalized_records => length(Events)},
                   RuntimeCounts)},
    DrainState = case maps:get(delivery_confirmed, TraceCleanup, false) of
        true -> confirmed;
        false -> failed
    end,
    CleanupState = case maps:get(trace_session_destroyed, TraceCleanup, false)
                        andalso TemporaryAgentUnloaded of
        true -> confirmed;
        false -> failed
    end,
    Completeness = #{schema => beam_flow_trace_completeness_v1,
                     state => State,
                     raw_frames => length(Events),
                     normalized_records => length(Events),
                     drain => DrainState,
                     cleanup => CleanupState,
                     loss => none},
    write_raw_events(filename:join(Output, "events.raw.etf"), Events,
                     67108864),
    write_jsonl(filename:join(Output, "events.normalized.jsonl"), Events),
    write_term_exclusive(filename:join(Output, "events.term"), Events),
    write_term_exclusive(filename:join(Output, "trace-completeness.term"),
                         Completeness),
    write_term_exclusive(filename:join(Output, "trace-manifest.term"), Manifest),
    write_binary_exclusive(filename:join(Output, "trace-status"),
                           atom_to_binary(State, utf8)),
    ok.

live_limit("infinity") -> infinity;
live_limit(Text) ->
    Value = decimal_integer(Text),
    true = Value > 0,
    Value.

live_duration_ms(infinity) -> infinity;
live_duration_ms(Seconds) when is_integer(Seconds), Seconds > 0 ->
    Seconds * 1000.

text_boolean("true") -> true;
text_boolean("false") -> false;
text_boolean(Other) -> error({invalid_boolean_text, Other}).

run_live_controlled(Target, ModuleNames, ProcessSelectors, FunctionPatterns,
                    EventSelectors, Limits, Backend, RunId, ControlPath) ->
    Controller = self(),
    Timeout = live_call_timeout(maps:get(duration_ms, Limits)),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Captured = try
            {ok, live_call(Target, beam_flow_runtime_agent, live_run,
                           [ModuleNames, ProcessSelectors, FunctionPatterns,
                            EventSelectors, Limits, Backend, RunId,
                            Controller], Timeout)}
        catch
            Class:Reason:Stack -> {error, {Class, Reason, Stack}}
        end,
        Controller ! {live_run_result, self(), Captured}
    end),
    await_live_worker(Target, RunId, Worker, Monitor, ControlPath, none).

live_call_timeout(infinity) -> infinity;
live_call_timeout(DurationMs) -> DurationMs + 10000.

await_live_worker(Target, RunId, Worker, Monitor, ControlPath, StopState) ->
    receive
        {live_run_result, Worker, Captured} ->
            erlang:demonitor(Monitor, [flush]),
            Captured;
        {'DOWN', Monitor, process, Worker, Reason} ->
            receive
                {live_run_result, Worker, Captured} -> Captured
            after 0 ->
                {error, {live_worker_down, Reason}}
            end
    after 100 ->
        NextStopState = poll_live_control(Target, RunId, ControlPath,
                                          StopState),
        await_live_worker(Target, RunId, Worker, Monitor, ControlPath,
                          NextStopState)
    end.

poll_live_control(Target, RunId, ControlPath, none) ->
    case read_live_control(ControlPath) of
        none -> none;
        {stop, Reason} -> request_remote_live_stop(Target, RunId, Reason)
    end;
poll_live_control(Target, RunId, _ControlPath, {pending, Reason}) ->
    request_remote_live_stop(Target, RunId, Reason);
poll_live_control(_Target, _RunId, _ControlPath, {sent, _} = Sent) -> Sent.

read_live_control(Path) ->
    case file:read_file(Path) of
        {error, enoent} -> none;
        {ok, Binary} ->
            _ = file:delete(Path),
            case string:trim(binary_to_list(Binary)) of
                "signal_int" -> {stop, signal_int};
                "signal_term" -> {stop, signal_term};
                Other -> error({invalid_live_control_request, Other})
            end;
        {error, Reason} -> error({live_control_read_failed, Reason})
    end.

request_remote_live_stop(Target, RunId, Reason) ->
    try live_call(Target, beam_flow_runtime_agent, stop_live,
                  [RunId, Reason], 2000) of
        ok -> {sent, Reason};
        {error, not_running} -> {pending, Reason};
        Other -> error({live_stop_request_failed, Other})
    catch
        Class:Failure -> error({live_stop_request_failed, Class, Failure})
    end.

start_live_controller(NodeText, CookiePath) ->
    Target = live_node_atom(NodeText),
    ControllerName = list_to_atom(peer:random_name(beam_flow_controller)),
    NameDomain = live_name_domain(NodeText),
    {ok, _} = net_kernel:start([ControllerName, NameDomain]),
    true = Target =/= node(),
    Cookie = read_live_cookie(CookiePath),
    true = erlang:set_cookie(node(), Cookie),
    case net_adm:ping(Target) of
        pong -> Target;
        pang -> error({live_node_unreachable, Target})
    end.

live_node_atom(Text) ->
    case string:split(Text, "@", all) of
        [Name, Host] when Name =/= [], Host =/= [] -> list_to_atom(Text);
        _ -> error({invalid_live_node_name, Text})
    end.

live_name_domain(NodeText) ->
    [_Name, Host] = string:split(NodeText, "@", all),
    case lists:member($., Host) of true -> longnames; false -> shortnames end.

read_live_cookie(Path) ->
    Text = string:trim(binary_to_list(read_binary(Path))),
    case length(Text) >= 1 andalso length(Text) =< 255 andalso
         lists:all(fun(Character) ->
             Character >= 33 andalso Character =< 126
         end, Text) of
        true -> list_to_atom(Text);
        false -> error(invalid_live_cookie_file)
    end.

preflight_live_node(Target, ModuleNames) ->
    Target = live_call(Target, erlang, node, []),
    Otp = live_call(Target, erlang, system_info, [otp_release]),
    Erts = live_call(Target, erlang, system_info, [version]),
    Paths = live_module_paths(Target, ModuleNames),
    Missing = [Module || {Module, non_existing} <- Paths],
    case Missing of [] -> ok; _ -> error({live_modules_not_loaded, Missing}) end,
    {module, trace} = live_call(Target, code, ensure_loaded, [trace]),
    SessionFunctions = [{trace, session_create, 3}, {trace, process, 4},
                        {trace, function, 4}, {trace, delivered, 2},
                        {trace, session_destroy, 1}],
    SessionCapable = lists:all(fun({Module, Function, Arity}) ->
        live_call(Target, erlang, function_exported,
                  [Module, Function, Arity])
    end, SessionFunctions),
    DbgCapable = case live_call(Target, code, ensure_loaded, [dbg]) of
        {module, dbg} ->
            lists:all(fun({Function, Arity}) ->
                live_call(Target, erlang, function_exported,
                          [dbg, Function, Arity])
            end, [{session_create, 1}, {session, 2},
                  {session_destroy, 1}, {tracer, 2}, {p, 2}, {tpl, 2}]);
        _ -> false
    end,
    LegacyFunctions = [{erlang, trace, 3}, {erlang, trace_pattern, 3},
                       {erlang, trace_info, 2},
                       {erlang, trace_delivered, 1}],
    LegacyCapable = lists:all(fun({Module, Function, Arity}) ->
        live_call(Target, erlang, function_exported,
                  [Module, Function, Arity])
    end, LegacyFunctions),
    #{node => Target,
      otp_release => Otp,
      erts_version => Erts,
      module_paths => Paths,
      capabilities => #{session => SessionCapable, dbg => DbgCapable,
                        legacy => LegacyCapable}}.

live_module_paths(Target, Modules) ->
    [{Module, live_call(Target, code, which, [Module])}
     || Module <- Modules].

select_trace_backend("auto", #{session := true}, _LegacyAuthorized) -> session;
select_trace_backend("auto", #{dbg := true}, _LegacyAuthorized) -> dbg;
select_trace_backend("auto", Capabilities, _LegacyAuthorized) ->
    error({no_isolated_live_trace_backend, Capabilities});
select_trace_backend("session", #{session := true}, _LegacyAuthorized) -> session;
select_trace_backend("session", Capabilities, _LegacyAuthorized) ->
    error({session_backend_unavailable, Capabilities});
select_trace_backend("dbg", #{dbg := true}, _LegacyAuthorized) -> dbg;
select_trace_backend("dbg", Capabilities, _LegacyAuthorized) ->
    error({dbg_backend_unavailable, Capabilities});
select_trace_backend("legacy", #{legacy := true}, true) -> legacy;
select_trace_backend("legacy", Capabilities, true) ->
    error({legacy_backend_unavailable, Capabilities});
select_trace_backend("legacy", _Capabilities, false) ->
    error(legacy_backend_requires_separate_authorization).

live_function_patterns([], _ModuleNames, GraphFunctions) ->
    lists:usort([flow_function_mfa(Function)
                 || Function <- GraphFunctions]);
live_function_patterns(Selectors, ModuleNames, GraphFunctions) ->
    lists:usort(lists:append(
      [live_function_selector(Selector, ModuleNames, GraphFunctions)
       || Selector <- Selectors])).

live_function_selector("all-supplied", _ModuleNames, GraphFunctions) ->
    [flow_function_mfa(Function) || Function <- GraphFunctions];
live_function_selector("all-loaded", _ModuleNames, _GraphFunctions) ->
    [{'_','_','_'}];
live_function_selector(Text, ModuleNames, GraphFunctions) ->
    case re:run(Text,
                "^([A-Za-z][A-Za-z0-9_@]*):([A-Za-z][A-Za-z0-9_@!?]*|_)/(\\d+|_)$",
                [{capture, [1, 2, 3], list}]) of
        {match, [ModuleText, FunctionText, ArityText]} ->
            Module = list_to_atom(ModuleText),
            case lists:member(Module, ModuleNames) of
                true -> ok;
                false -> error({live_function_module_not_in_graph, Module})
            end,
            Function = case FunctionText of
                "_" -> '_';
                _ -> list_to_atom(FunctionText)
            end,
            Arity = case ArityText of
                "_" -> '_';
                _ -> decimal_integer(ArityText)
            end,
            Matches = [MFA || Record <- GraphFunctions,
                               MFA <- [flow_function_mfa(Record)],
                               element(1, MFA) =:= Module,
                               (Function =:= '_' orelse
                                element(2, MFA) =:= Function),
                               (Arity =:= '_' orelse
                                element(3, MFA) =:= Arity)],
            case Matches of
                [] -> error({live_function_selector_not_found, Text});
                _ -> Matches
            end;
        nomatch -> error({invalid_live_function_selector, Text})
    end.

unload_live_agent(Target) ->
    Delete = live_call(Target, code, delete, [beam_flow_runtime_agent]),
    Purge = live_call(Target, code, purge, [beam_flow_runtime_agent]),
    LoadedAfter = live_call(Target, code, is_loaded,
                            [beam_flow_runtime_agent]),
    #{delete => Delete, purge => Purge, loaded_after => LoadedAfter,
      unloaded => LoadedAfter =:= false}.

live_call(Target, Module, Function, Arguments) ->
    live_call(Target, Module, Function, Arguments, 5000).

live_call(Target, Module, Function, Arguments, Timeout) ->
    erpc:call(Target, Module, Function, Arguments, Timeout).

flow_isolated(Output, GraphDir, ScenarioPath,
              IsolationRequestedText, IsolationEffectiveText, AgentBeam) ->
    {module, peer} = code:ensure_loaded(peer),
    Graph = consult_one(filename:join(GraphDir, "flow-ir.term")),
    beam_flow_ir_v1 = maps:get(schema, Graph),
    complete = maps:get(state, Graph),
    Scenario = consult_one(ScenarioPath),
    _ = validate_scenario(Scenario),
    ModuleSpecs = isolated_module_specs(maps:get(modules, Graph)),
    RuntimePatterns = isolated_runtime_patterns(Graph),
    validate_scenario_modules(Scenario, ModuleSpecs),
    AgentBinary = read_binary(AgentBeam),
    {ok, {beam_flow_runtime_agent, [{exports, _}]}} =
        beam_lib:chunks(AgentBinary, [exports]),
    Requested = isolation_atom(IsolationRequestedText),
    Effective = isolation_atom(IsolationEffectiveText),
    process_flag(trap_exit, true),
    Name = peer:random_name(beam_flow),
    ErlPath = getenv_required("BEAM_TOOLKIT_ERL_PATH"),
    Options = #{name => Name,
                connection => standard_io,
                exec => ErlPath,
                args => ["-noinput", "-noshell"],
                wait_boot => 10000,
                shutdown => {halt, 5000},
                peer_down => continue},
    {ok, Peer, Node} = peer:start_link(Options),
    true = is_atom(Node),
    true = Node =/= nonode@nohost,
    false = lists:member(Node, [node() | nodes()]),
    Monitor = erlang:monitor(process, Peer),
    Timeout = maps:get(timeout_ms, Scenario),
    RunOutcome = try
        {module, beam_flow_runtime_agent} = peer:call(
          Peer, code, load_binary,
          [beam_flow_runtime_agent, AgentBeam, AgentBinary], 10000),
        peer:call(Peer, beam_flow_runtime_agent, run,
                  [Scenario, ModuleSpecs,
                   #{controller_node => node(), target_node => Node},
                   RuntimePatterns],
                  Timeout + 10000)
    catch
        Class:Reason:Stack ->
            #{schema => beam_flow_runtime_result_v1,
              state => partial,
              events => [],
              scenario => #{status => failed, assertions_passed => 0,
                            reason => unicode:characters_to_binary(
                              io_lib:format("~tp", [{Class, Reason, Stack}]))},
              on_load => #{declared => declared_on_load_modules(ModuleSpecs),
                           invoked => []},
              instrumentation => #{function_patterns => RuntimePatterns,
                                   function_match_counts => []},
              trace_cleanup => #{trace_session_destroyed => false,
                                 delivery_confirmed => false}}
    end,
    StopResult = try peer:stop(Peer)
                 catch StopClass:StopReason -> {StopClass, StopReason}
                 end,
    PeerDown = receive
        {'DOWN', Monitor, process, Peer, _Reason} -> true
    after 5000 ->
        false
    end,
    ControllerAlive = is_process_alive(Peer),
    PeerStopped = StopResult =:= ok andalso PeerDown andalso
                  not ControllerAlive,
    beam_flow_runtime_result_v1 = maps:get(schema, RunOutcome),
    Events0 = maps:get(events, RunOutcome),
    Events = correlate_runtime_events(Events0),
    TraceCleanup = maps:get(trace_cleanup, RunOutcome),
    State0 = maps:get(state, RunOutcome),
    State = case State0 =:= complete andalso PeerStopped andalso
                 maps:get(trace_session_destroyed, TraceCleanup, false) of
        true -> complete;
        false -> partial
    end,
    RuntimeOverlay = write_runtime_artifacts(Output, Graph, Events, State),
    RuntimeCounts = maps:get(runtime_counts, RuntimeOverlay),
    Runtime = #{otp_release => peer_runtime_value(RunOutcome, otp_release),
                erts_version => peer_runtime_value(RunOutcome, erts_version),
                erl_path => ErlPath,
                erlc_path => getenv_required("BEAM_TOOLKIT_ERLC_PATH"),
                escript_path => getenv_required("BEAM_TOOLKIT_ESCRIPT_PATH")},
    Manifest = #{schema => beam_flow_trace_v1,
                 version => 1,
                 state => State,
                 mode => isolated_runtime,
                 node => Node,
                 controller_node => node(),
                 runtime => Runtime,
                 isolation => #{requested => Requested,
                                effective => Effective,
                                downgraded => Requested =/= Effective,
                                security_sandbox => Effective =:= namespace},
                 scenario => maps:get(scenario, RunOutcome),
                 instrumentation => maps:get(instrumentation, RunOutcome),
                 on_load => maps:get(on_load, RunOutcome),
                 cleanup => TraceCleanup#{peer_stopped => PeerStopped,
                                          peer_down_received => PeerDown,
                                          controller_alive_after_stop =>
                                              ControllerAlive},
                 runtime_overlay => #{schema => maps:get(schema,
                                                         RuntimeOverlay),
                                      counts => RuntimeCounts},
                 counts => maps:merge(
                   #{events => length(Events),
                     raw_frames => length(Events),
                     normalized_records => length(Events)},
                   RuntimeCounts)},
    DrainState = case maps:get(delivery_confirmed, TraceCleanup, false) of
        true -> confirmed;
        false -> failed
    end,
    CleanupState = case PeerStopped andalso
                        maps:get(trace_session_destroyed, TraceCleanup, false) of
        true -> confirmed;
        false -> failed
    end,
    Completeness = #{schema => beam_flow_trace_completeness_v1,
                     state => State,
                     raw_frames => length(Events),
                     normalized_records => length(Events),
                     drain => DrainState,
                     cleanup => CleanupState,
                     loss => none},
    write_raw_events(filename:join(Output, "events.raw.etf"), Events,
                     67108864),
    write_jsonl(filename:join(Output, "events.normalized.jsonl"), Events),
    write_term_exclusive(filename:join(Output, "events.term"), Events),
    write_term_exclusive(filename:join(Output, "trace-completeness.term"),
                         Completeness),
    write_term_exclusive(filename:join(Output, "trace-manifest.term"), Manifest),
    write_binary_exclusive(filename:join(Output, "trace-status"),
                           atom_to_binary(State, utf8)),
    ok.

isolated_runtime_patterns(Graph) ->
    Internal = [flow_function_mfa(Function)
                || Function <- maps:get(functions, Graph)],
    External = [MFA || Edge <- maps:get(call_edges, Graph),
                       maps:get(target_kind, Edge) =:= external,
                       MFA <- [maps:get(target_mfa, Edge, undefined)],
                       is_tuple(MFA), tuple_size(MFA) =:= 3],
    lists:usort(Internal ++ External).

write_raw_events(Path, Events, MaximumFrameBytes) ->
    {ok, Device} = file:open(Path, [write, exclusive, raw, binary]),
    try
        lists:foreach(fun(Event) ->
            Encoded = maps:get(raw_etf_base64, Event),
            case is_binary(Encoded) of
                true -> ok;
                false -> error({runtime_event_missing_raw_etf,
                                maps:get(sequence, Event)})
            end,
            Payload = base64:decode(Encoded),
            write_framed_event(Device, Payload, MaximumFrameBytes)
        end, Events)
    after
        ok = file:close(Device)
    end.

write_framed_event(Device, Payload, MaximumFrameBytes) ->
    Length = byte_size(Payload),
    case Length > 0 andalso Length =< MaximumFrameBytes of
        true ->
            ok = file:write(Device,
                            <<Length:64/unsigned-big, Payload/binary>>);
        false -> error({invalid_etf_frame_length, Length,
                        MaximumFrameBytes})
    end.

write_jsonl(Path, Events) ->
    {ok, Device} = file:open(Path, [write, exclusive, raw, binary]),
    try
        lists:foreach(fun(Event) ->
            Json = iolist_to_binary(json:encode(json_safe(Event))),
            ok = file:write(Device, <<Json/binary, "\n">>)
        end, Events)
    after
        ok = file:close(Device)
    end.

correlate_runtime_events(Events) ->
    {Reversed, _Stacks} = lists:foldl(fun(Event, {Acc, Stacks0}) ->
        {Correlated, Stacks} = update_call_state(Event, Stacks0),
        {[Correlated | Acc], Stacks}
    end, {[], #{}}, Events),
    lists:reverse(Reversed).

update_call_state(Event = #{kind := call, pid := Pid, mfa := MFA}, Stacks) ->
    Stack = maps:get(Pid, Stacks, []),
    NewStack = [MFA | Stack],
    {Event#{correlation => exact, call_depth => length(NewStack)},
     Stacks#{Pid => NewStack}};
update_call_state(Event = #{kind := Kind, pid := Pid, mfa := MFA}, Stacks)
  when Kind =:= return_from; Kind =:= exception_from ->
    Stack = maps:get(Pid, Stacks, []),
    {Correlation, NewStack} = pop_runtime_frame(MFA, Stack),
    {Event#{correlation => Correlation, call_depth => length(NewStack)},
     Stacks#{Pid => NewStack}};
update_call_state(Event = #{kind := return_to, pid := Pid}, Stacks) ->
    Stack = maps:get(Pid, Stacks, []),
    {Event#{correlation => partial, call_depth => length(Stack)}, Stacks};
update_call_state(Event, Stacks) ->
    Pid = maps:get(pid, Event, undefined),
    Stack = maps:get(Pid, Stacks, []),
    {Event#{correlation => not_applicable, call_depth => length(Stack)}, Stacks}.

pop_runtime_frame(_MFA, []) -> {broken, []};
pop_runtime_frame(MFA, [MFA | Rest]) -> {exact, Rest};
pop_runtime_frame(MFA, Stack) ->
    case drop_through_runtime_frame(MFA, Stack) of
        not_found -> {broken, Stack};
        Rest -> {partial, Rest}
    end.

drop_through_runtime_frame(_MFA, []) -> not_found;
drop_through_runtime_frame(MFA, [MFA | Rest]) -> Rest;
drop_through_runtime_frame(MFA, [_ | Rest]) ->
    drop_through_runtime_frame(MFA, Rest).

write_runtime_artifacts(Output, Graph, Events, State) ->
    StaticIndex = runtime_static_index(Graph),
    ModuleSet = maps:from_list(
      [{maps:get(module, Module), true} || Module <- maps:get(modules, Graph)]),
    Timeline = [attach_runtime_static_match(Event, StaticIndex, ModuleSet)
                || Event <- Events],
    Processes = build_runtime_processes(Timeline),
    ProcessIndex = maps:from_list(
      [{maps:get(pid, Process), maps:get(id, Process)}
       || Process <- Processes]),
    CallObservations = runtime_call_observations(Timeline, ProcessIndex),
    FunctionSummaries = runtime_function_summaries(
      Graph, Timeline, StaticIndex),
    CallEdges = runtime_call_edges(CallObservations, StaticIndex),
    SpawnEdges = runtime_spawn_edges(Timeline, ProcessIndex),
    MessageEdges = runtime_message_edges(Timeline, ProcessIndex),
    Unmatched = [runtime_unmatched_record(Event)
                 || Event <- Timeline,
                    maps:get(status, maps:get(static_match, Event)) =:=
                        unmatched],
    RuntimeEdges = #{schema => beam_flow_runtime_edges_v1,
                     state => State,
                     call_edges => CallEdges,
                     spawn_edges => SpawnEdges,
                     message_edges => MessageEdges},
    RuntimeCounts = #{runtime_processes => length(Processes),
                      runtime_functions => length(FunctionSummaries),
                      runtime_call_observations => length(CallObservations),
                      runtime_call_edges => length(CallEdges),
                      runtime_spawn_edges => length(SpawnEdges),
                      runtime_message_edges => length(MessageEdges),
                      runtime_unmatched => length(Unmatched),
                      runtime_timeline => length(Timeline)},
    Overlay = #{schema => beam_flow_runtime_overlay_v1,
                version => 1,
                state => State,
                static_counts => maps:get(counts, Graph),
                static_call_edges_sha256 => crypto:hash(
                  sha256, term_to_binary(maps:get(call_edges, Graph),
                                         [deterministic])),
                functions => FunctionSummaries,
                call_observations => CallObservations,
                edges => RuntimeEdges,
                process_ids => [maps:get(id, Process)
                                || Process <- Processes],
                unmatched_sequences => [maps:get(sequence, Event)
                                        || Event <- Unmatched],
                runtime_counts => RuntimeCounts},
    write_term_exclusive(filename:join(Output, "runtime-processes.term"),
                         Processes),
    write_term_exclusive(filename:join(Output, "runtime-edges.term"),
                         RuntimeEdges),
    write_term_exclusive(filename:join(Output, "runtime-unmatched.term"),
                         Unmatched),
    write_term_exclusive(filename:join(Output, "runtime-overlay.term"),
                         Overlay),
    write_json(filename:join(Output, "timeline.json"), Timeline),
    write_runtime_dot(filename:join(Output, "runtime.dot"),
                      FunctionSummaries, Processes, RuntimeEdges),
    write_runtime_flow_html(filename:join(Output, "flow.html"), Graph,
                            Overlay, Processes, RuntimeEdges, Timeline),
    Overlay.

runtime_static_index(Graph) ->
    maps:from_list([{flow_function_mfa(Function),
                     #{id => maps:get(id, Function), record => Function}}
                    || Function <- maps:get(functions, Graph)]).

attach_runtime_static_match(Event, StaticIndex, ModuleSet) ->
    case maps:find(mfa, Event) of
        error ->
            Event#{static_match =>
                       #{status => not_applicable,
                         reason => event_has_no_mfa}};
        {ok, MFA} ->
            case maps:find(MFA, StaticIndex) of
                {ok, Static} ->
                    Event#{static_match =>
                               #{status => matched,
                                 function_id => maps:get(id, Static)}};
                error ->
                    Reason = runtime_unmatched_reason(MFA, ModuleSet),
                    Event#{static_match =>
                               #{status => unmatched, reason => Reason}}
            end
    end.

runtime_unmatched_reason({Module, Function, Arity}, ModuleSet) ->
    IsBuiltin = try erlang:is_builtin(Module, Function, Arity)
                catch _:_ -> false
                end,
    case IsBuiltin of
        true -> bif;
        _ ->
            case maps:is_key(Module, ModuleSet) of
                true -> insufficient_static_evidence;
                false -> unsupplied_module
            end
    end;
runtime_unmatched_reason(_Other, _ModuleSet) -> insufficient_static_evidence.

runtime_unmatched_record(Event) ->
    Match = maps:get(static_match, Event),
    Event#{reason => maps:get(reason, Match)}.

build_runtime_processes(Timeline) ->
    Pids = runtime_pid_order(Timeline),
    Index = maps:from_list(
      [{Pid, {runtime_process, Ordinal}}
       || {Pid, Ordinal} <- lists:zip(Pids,
                                      lists:seq(1, length(Pids)))]),
    [runtime_process_record(Pid, maps:get(Pid, Index), Index, Timeline)
     || Pid <- Pids].

runtime_pid_order(Timeline) ->
    {_Seen, Reversed} = lists:foldl(fun(Event, {Seen0, Acc0}) ->
        lists:foldl(fun(Pid, {Seen, Acc}) ->
            case maps:is_key(Pid, Seen) of
                true -> {Seen, Acc};
                false -> {Seen#{Pid => true}, [Pid | Acc]}
            end
        end, {Seen0, Acc0}, runtime_event_pids(Event))
    end, {#{}, []}, Timeline),
    lists:reverse(Reversed).

runtime_event_pids(Event) ->
    [Value || Key <- [pid, child, parent, receiver],
              Value <- [maps:get(Key, Event, undefined)],
              is_portable_pid(Value)].

is_portable_pid(#{term_type := pid, text := Text}) when is_binary(Text) -> true;
is_portable_pid(_) -> false.

runtime_process_record(Pid, Id, Index, Timeline) ->
    Mentioned = [Event || Event <- Timeline,
                          lists:member(Pid, runtime_event_pids(Event))],
    OwnedEvents = [Event || Event <- Timeline,
                            maps:get(pid, Event, undefined) =:= Pid],
    Sequences = [maps:get(sequence, Event) || Event <- Mentioned],
    {Parent, Entry, SpawnSequence} = runtime_process_parent(Pid, Timeline),
    ExitReason = case [maps:get(reason, Event)
                       || Event <- OwnedEvents,
                          maps:get(kind, Event) =:= exit,
                          maps:is_key(reason, Event)] of
        [Reason | _] -> Reason;
        [] -> undefined
    end,
    RegisteredNames = lists:usort(
      [maps:get(registered_name, Event)
       || Event <- OwnedEvents,
          maps:get(kind, Event) =:= register,
          maps:is_key(registered_name, Event)]),
    #{id => Id,
      pid => Pid,
      node => maps:get(node, Pid, undefined),
      first_sequence => lists:min(Sequences),
      last_sequence => lists:max(Sequences),
      event_count => length(OwnedEvents),
      parent_id => maps:get(Parent, Index, undefined),
      parent_pid => Parent,
      spawn_sequence => SpawnSequence,
      entry => Entry,
      exit_reason => ExitReason,
      registered_names => RegisteredNames}.

runtime_process_parent(Pid, Timeline) ->
    Spawned = [{maps:get(parent, Event), maps:get(entry, Event, undefined),
                maps:get(sequence, Event)}
               || Event <- Timeline,
                  maps:get(kind, Event) =:= spawned,
                  maps:get(pid, Event, undefined) =:= Pid,
                  is_portable_pid(maps:get(parent, Event, undefined))],
    Spawn = [{maps:get(pid, Event), maps:get(entry, Event, undefined),
              maps:get(sequence, Event)}
             || Event <- Timeline,
                maps:get(kind, Event) =:= spawn,
                maps:get(child, Event, undefined) =:= Pid,
                is_portable_pid(maps:get(pid, Event, undefined))],
    case Spawned ++ Spawn of
        [{Parent, Entry, Sequence} | _] -> {Parent, Entry, Sequence};
        [] -> {undefined, undefined, undefined}
    end.

runtime_call_observations(Timeline, ProcessIndex) ->
    {Stacks, Completed0} = lists:foldl(
      fun runtime_call_observation_step/2, {#{}, []},
      [{Event, ProcessIndex} || Event <- Timeline]),
    Open = [Frame#{outcome => open, correlation => missing_return}
            || {_Pid, Frames} <- maps:to_list(Stacks), Frame <- Frames],
    lists:sort(fun(A, B) ->
        maps:get(call_sequence, A) =< maps:get(call_sequence, B)
    end, Completed0 ++ Open).

runtime_call_observation_step(
  {Event = #{kind := call, pid := Pid, mfa := MFA}, ProcessIndex},
  {Stacks, Completed}) ->
    Stack = maps:get(Pid, Stacks, []),
    Caller = case Stack of
        [#{mfa := CallerMFA} | _] -> CallerMFA;
        [] -> {process_entry, maps:get(Pid, ProcessIndex, undefined)}
    end,
    Frame = #{mfa => MFA,
              caller => Caller,
              pid => Pid,
              process_id => maps:get(Pid, ProcessIndex, undefined),
              call_sequence => maps:get(sequence, Event),
              start_timestamp => maps:get(timestamp, Event, undefined),
              static_match => maps:get(static_match, Event),
              outcome => open},
    {Stacks#{Pid => [Frame | Stack]}, Completed};
runtime_call_observation_step(
  {Event = #{kind := Kind, pid := Pid, mfa := MFA}, _ProcessIndex},
  {Stacks, Completed}) when Kind =:= return_from;
                            Kind =:= exception_from ->
    Stack = maps:get(Pid, Stacks, []),
    case take_runtime_observation(MFA, Stack, []) of
        not_found -> {Stacks, Completed};
        {Frame, Rest, Skipped} ->
            Outcome = case Kind of
                return_from -> returned;
                exception_from -> exception
            end,
            CompletedFrame0 = Frame#{outcome => Outcome,
                                     return_sequence =>
                                         maps:get(sequence, Event),
                                     end_timestamp =>
                                         maps:get(timestamp, Event,
                                                  undefined),
                                     correlation =>
                                         maps:get(correlation, Event,
                                                  exact)},
            CompletedFrame = maybe_runtime_duration(CompletedFrame0),
            Missing = [SkippedFrame#{outcome => open,
                                     correlation => missing_return}
                       || SkippedFrame <- Skipped],
            {Stacks#{Pid => Rest}, Missing ++ [CompletedFrame | Completed]}
    end;
runtime_call_observation_step({_Event, _ProcessIndex}, State) -> State.

take_runtime_observation(_MFA, [], _Skipped) -> not_found;
take_runtime_observation(MFA, [Frame = #{mfa := MFA} | Rest], Skipped) ->
    {Frame, Rest, lists:reverse(Skipped)};
take_runtime_observation(MFA, [Frame | Rest], Skipped) ->
    take_runtime_observation(MFA, Rest, [Frame | Skipped]).

maybe_runtime_duration(Frame) ->
    case runtime_timestamp_delta(maps:get(start_timestamp, Frame),
                                 maps:get(end_timestamp, Frame)) of
        undefined -> Frame;
        {Value, Unit} -> Frame#{duration => Value, duration_unit => Unit}
    end.

runtime_timestamp_delta(Start, End) when is_integer(Start), is_integer(End),
                                          End >= Start ->
    {End - Start, native_trace_time};
runtime_timestamp_delta({Mega1, Sec1, Micro1}, {Mega2, Sec2, Micro2}) ->
    Start = (Mega1 * 1000000 + Sec1) * 1000000 + Micro1,
    End = (Mega2 * 1000000 + Sec2) * 1000000 + Micro2,
    case End >= Start of
        true -> {End - Start, microsecond};
        false -> undefined
    end;
runtime_timestamp_delta(_Start, _End) -> undefined.

runtime_function_summaries(Graph, Timeline, StaticIndex) ->
    Base = maps:from_list(
      [{flow_function_mfa(Function),
        #{mfa => flow_function_mfa(Function),
          static_id => maps:get(id, Function),
          static_status => matched,
          observed_calls => 0,
          observed_returns => 0,
          observed_exceptions => 0,
          sequences => [],
          process_ids => []}}
       || Function <- maps:get(functions, Graph)]),
    Acc = lists:foldl(fun(Event, Summaries) ->
        case maps:find(mfa, Event) of
            error -> Summaries;
            {ok, MFA} ->
                Summary0 = case maps:find(MFA, Summaries) of
                    {ok, Existing} -> Existing;
                    error ->
                        Match = maps:get(static_match, Event),
                        #{mfa => MFA,
                          static_id => undefined,
                          static_status => unmatched,
                          reason => maps:get(reason, Match),
                          observed_calls => 0,
                          observed_returns => 0,
                          observed_exceptions => 0,
                          sequences => [],
                          process_ids => []}
                end,
                Summary = update_runtime_function_summary(Summary0, Event),
                Summaries#{MFA => Summary}
        end
    end, Base, Timeline),
    _ = StaticIndex,
    lists:sort(fun(A, B) ->
        mfa_text(maps:get(mfa, A)) =< mfa_text(maps:get(mfa, B))
    end, maps:values(Acc)).

update_runtime_function_summary(Summary0, Event) ->
    Kind = maps:get(kind, Event),
    Summary1 = case Kind of
        call -> Summary0#{observed_calls :=
                              maps:get(observed_calls, Summary0) + 1};
        return_from -> Summary0#{observed_returns :=
                                     maps:get(observed_returns, Summary0) + 1};
        exception_from -> Summary0#{observed_exceptions :=
                                        maps:get(observed_exceptions,
                                                 Summary0) + 1};
        _ -> Summary0
    end,
    Sequence = maps:get(sequence, Event),
    Pid = maps:get(pid, Event, undefined),
    Summary1#{sequences := maps:get(sequences, Summary1) ++ [Sequence],
              process_ids := lists:usort(
                [Pid | maps:get(process_ids, Summary1)])}.

runtime_call_edges(Observations, StaticIndex) ->
    Grouped = lists:foldl(fun(Observation, Acc) ->
        Caller = maps:get(caller, Observation),
        Target = maps:get(mfa, Observation),
        Key = {Caller, Target},
        Entry0 = maps:get(Key, Acc,
                          #{caller => Caller, target_mfa => Target,
                            observed_count => 0, returns => 0,
                            exceptions => 0, open => 0,
                            sequences => []}),
        Outcome = maps:get(outcome, Observation),
        Entry1 = Entry0#{observed_count :=
                             maps:get(observed_count, Entry0) + 1,
                         sequences := maps:get(sequences, Entry0) ++
                                      [maps:get(call_sequence, Observation)]},
        Entry = case Outcome of
            returned -> Entry1#{returns := maps:get(returns, Entry1) + 1};
            exception -> Entry1#{exceptions :=
                                     maps:get(exceptions, Entry1) + 1};
            _ -> Entry1#{open := maps:get(open, Entry1) + 1}
        end,
        Acc#{Key => Entry}
    end, #{}, Observations),
    Values = lists:sort(fun(A, B) ->
        flow_text({maps:get(caller, A), maps:get(target_mfa, A)}) =<
        flow_text({maps:get(caller, B), maps:get(target_mfa, B)})
    end, maps:values(Grouped)),
    [runtime_call_edge_record(Entry, Ordinal, StaticIndex)
     || {Entry, Ordinal} <- lists:zip(
          Values, lists:seq(1, length(Values)))].

runtime_call_edge_record(Entry, Ordinal, StaticIndex) ->
    Caller = maps:get(caller, Entry),
    Target = maps:get(target_mfa, Entry),
    CallerId = runtime_call_node_id(Caller, StaticIndex),
    TargetId = runtime_call_node_id(Target, StaticIndex),
    Entry#{id => {runtime_call_edge, Ordinal},
           caller_id => CallerId,
           target_id => TargetId,
           status => observed,
           runtime_only => not maps:is_key(Target, StaticIndex)}.

runtime_call_node_id({process_entry, ProcessId}, _StaticIndex) ->
    {process_entry, ProcessId};
runtime_call_node_id(MFA, StaticIndex) ->
    case maps:find(MFA, StaticIndex) of
        {ok, Static} -> maps:get(id, Static);
        error -> {runtime_function, MFA}
    end.

runtime_spawn_edges(Timeline, ProcessIndex) ->
    Candidates0 = [#{parent_pid => maps:get(pid, Event),
                     child_pid => maps:get(child, Event),
                     entry => maps:get(entry, Event, undefined),
                     sequence => maps:get(sequence, Event)}
                   || Event <- Timeline,
                      maps:get(kind, Event) =:= spawn,
                      is_portable_pid(maps:get(pid, Event, undefined)),
                      is_portable_pid(maps:get(child, Event, undefined))],
    ExistingPairs = maps:from_list(
      [{{maps:get(parent_pid, Edge), maps:get(child_pid, Edge)}, true}
       || Edge <- Candidates0]),
    Candidates = Candidates0 ++
      [#{parent_pid => maps:get(parent, Event),
         child_pid => maps:get(pid, Event),
         entry => maps:get(entry, Event, undefined),
         sequence => maps:get(sequence, Event)}
       || Event <- Timeline,
          maps:get(kind, Event) =:= spawned,
          is_portable_pid(maps:get(parent, Event, undefined)),
          is_portable_pid(maps:get(pid, Event, undefined)),
          not maps:is_key({maps:get(parent, Event), maps:get(pid, Event)},
                          ExistingPairs)],
    [Edge#{id => {runtime_spawn_edge, Ordinal},
           parent_id => maps:get(maps:get(parent_pid, Edge), ProcessIndex),
           child_id => maps:get(maps:get(child_pid, Edge), ProcessIndex),
           status => observed}
     || {Edge, Ordinal} <- lists:zip(
          Candidates, lists:seq(1, length(Candidates)))].

runtime_message_edges(Timeline, ProcessIndex) ->
    Sends = [#{send_sequence => maps:get(sequence, Event),
               sender => maps:get(pid, Event, undefined),
               receiver => maps:get(receiver, Event, undefined),
               message => maps:get(message, Event, undefined),
               send_kind => maps:get(kind, Event)}
             || Event <- Timeline,
                lists:member(maps:get(kind, Event),
                             [send, send_to_non_existing_process])],
    Receives = [#{receive_sequence => maps:get(sequence, Event),
                  receiver => maps:get(pid, Event, undefined),
                  message => maps:get(message, Event, undefined)}
                || Event <- Timeline,
                   maps:get(kind, Event) =:= 'receive'],
    {Matches, UnmatchedReceives} = match_runtime_messages(
      Receives, Sends, #{}, #{}, []),
    SendEdges = [runtime_send_edge(Send, maps:get(
                                    maps:get(send_sequence, Send), Matches,
                                    undefined), ProcessIndex)
                 || Send <- Sends],
    ReceiveOnly = [#{sender => undefined,
                     receiver => maps:get(receiver, Receive),
                     sender_id => undefined,
                     receiver_id => runtime_endpoint_id(
                       maps:get(receiver, Receive), ProcessIndex),
                     message => maps:get(message, Receive),
                     send_sequence => undefined,
                     receive_sequence => maps:get(receive_sequence, Receive),
                     status => unmatched_send}
                   || Receive <- UnmatchedReceives],
    Edges = SendEdges ++ ReceiveOnly,
    [Edge#{id => {runtime_message_edge, Ordinal}}
     || {Edge, Ordinal} <- lists:zip(
          Edges, lists:seq(1, length(Edges)))].

match_runtime_messages([], _Sends, _Used, Matches, Unmatched) ->
    {Matches, lists:reverse(Unmatched)};
match_runtime_messages([Receive | Rest], Sends, Used, Matches, Unmatched) ->
    case find_runtime_send(Receive, Sends, Used) of
        none -> match_runtime_messages(Rest, Sends, Used, Matches,
                                       [Receive | Unmatched]);
        {SendSequence, ReceiveSequence} ->
            match_runtime_messages(
              Rest, Sends, Used#{SendSequence => true},
              Matches#{SendSequence => ReceiveSequence}, Unmatched)
    end.

find_runtime_send(_Receive, [], _Used) -> none;
find_runtime_send(Receive, [Send | Rest], Used) ->
    SendSequence = maps:get(send_sequence, Send),
    ReceiveSequence = maps:get(receive_sequence, Receive),
    Matches = not maps:is_key(SendSequence, Used) andalso
              SendSequence < ReceiveSequence andalso
              maps:get(receiver, Send) =:= maps:get(receiver, Receive) andalso
              maps:get(message, Send) =:= maps:get(message, Receive),
    case Matches of
        true -> {SendSequence, ReceiveSequence};
        false -> find_runtime_send(Receive, Rest, Used)
    end.

runtime_send_edge(Send, ReceiveSequence, ProcessIndex) ->
    Sender = maps:get(sender, Send),
    Receiver = maps:get(receiver, Send),
    #{sender => Sender,
      receiver => Receiver,
      sender_id => runtime_endpoint_id(Sender, ProcessIndex),
      receiver_id => runtime_endpoint_id(Receiver, ProcessIndex),
      message => maps:get(message, Send),
      send_sequence => maps:get(send_sequence, Send),
      receive_sequence => ReceiveSequence,
      status => case ReceiveSequence of
          undefined -> unmatched_receive;
          _ -> matched
      end}.

runtime_endpoint_id(Value, ProcessIndex) ->
    case maps:find(Value, ProcessIndex) of
        {ok, ProcessId} -> ProcessId;
        error -> {runtime_endpoint, Value}
    end.

write_runtime_dot(Path, Functions, Processes, RuntimeEdges) ->
    FunctionTerms = [{runtime_function_node, maps:get(mfa, Function)}
                     || Function <- Functions],
    ProcessTerms = [{runtime_process_node, maps:get(id, Process)}
                    || Process <- Processes],
    Terms = FunctionTerms ++ ProcessTerms,
    Index = maps:from_list(
      [{Term, "r" ++ integer_to_list(Ordinal)}
       || {Term, Ordinal} <- lists:zip(Terms,
                                       lists:seq(1, length(Terms)))]),
    FunctionNodes = [runtime_dot_function_node(Function, Index)
                     || Function <- Functions],
    ProcessNodes = [runtime_dot_process_node(Process, Index)
                    || Process <- Processes],
    CallLines = [runtime_dot_call_edge(Edge, Index)
                 || Edge <- maps:get(call_edges, RuntimeEdges)],
    SpawnLines = [runtime_dot_spawn_edge(Edge, Index)
                  || Edge <- maps:get(spawn_edges, RuntimeEdges)],
    MessageLines = [runtime_dot_message_edge(Edge, Index)
                    || Edge <- maps:get(message_edges, RuntimeEdges)],
    write_binary_exclusive(Path,
      ["digraph beam_runtime {\n  rankdir=LR;\n",
       "  graph [charset=\"UTF-8\"];\n",
       FunctionNodes, ProcessNodes, CallLines, SpawnLines, MessageLines,
       "}\n"]).

runtime_dot_function_node(Function, Index) ->
    MFA = maps:get(mfa, Function),
    Observed = maps:get(observed_calls, Function) > 0,
    RuntimeOnly = maps:get(static_status, Function) =:= unmatched,
    Class = case {RuntimeOnly, Observed} of
        {true, _} -> "runtime-only";
        {false, true} -> "runtime-observed";
        _ -> "static-unobserved"
    end,
    Color = case Class of
        "runtime-only" -> "#f59e0b";
        "runtime-observed" -> "#10b981";
        _ -> "#64748b"
    end,
    io_lib:format(
      "  ~s [shape=box,class=\"~s\",color=\"~s\",label=\"~s\\ncalls=~B\"];~n",
      [maps:get({runtime_function_node, MFA}, Index), Class, Color,
       dot_escape(mfa_text(MFA)), maps:get(observed_calls, Function)]).

runtime_dot_process_node(Process, Index) ->
    Id = maps:get(id, Process),
    io_lib:format(
      "  ~s [shape=ellipse,class=\"runtime-process\",label=\"~s\"];~n",
      [maps:get({runtime_process_node, Id}, Index),
       dot_escape(flow_text(Id))]).

runtime_dot_call_edge(Edge, Index) ->
    Caller = maps:get(caller, Edge),
    Target = maps:get(target_mfa, Edge),
    case {runtime_dot_function_term(Caller, Index),
          maps:find({runtime_function_node, Target}, Index)} of
        {{ok, Source}, {ok, Destination}} ->
            io_lib:format(
              "  ~s -> ~s [class=\"runtime-observed\",color=\"#10b981\",label=\"calls ~B\"];~n",
              [Source, Destination, maps:get(observed_count, Edge)]);
        _ -> []
    end.

runtime_dot_function_term({process_entry, _}, _Index) -> error;
runtime_dot_function_term(MFA, Index) ->
    maps:find({runtime_function_node, MFA}, Index).

runtime_dot_spawn_edge(Edge, Index) ->
    case {maps:find({runtime_process_node, maps:get(parent_id, Edge)}, Index),
          maps:find({runtime_process_node, maps:get(child_id, Edge)}, Index)} of
        {{ok, Source}, {ok, Destination}} ->
            io_lib:format(
              "  ~s -> ~s [class=\"runtime-spawn\",color=\"#38bdf8\",label=\"spawn\"];~n",
              [Source, Destination]);
        _ -> []
    end.

runtime_dot_message_edge(Edge, Index) ->
    case {maps:find({runtime_process_node, maps:get(sender_id, Edge)}, Index),
          maps:find({runtime_process_node, maps:get(receiver_id, Edge)}, Index)} of
        {{ok, Source}, {ok, Destination}} ->
            io_lib:format(
              "  ~s -> ~s [class=\"runtime-message\",style=dashed,color=\"#a78bfa\",label=\"message/~s\"];~n",
              [Source, Destination,
               dot_escape(atom_to_list(maps:get(status, Edge)))]);
        _ -> []
    end.

write_runtime_flow_html(Path, Graph, Overlay, Processes, RuntimeEdges,
                        Timeline) ->
    Data = #{static => Graph, runtime => Overlay,
             processes => Processes, edges => RuntimeEdges,
             timeline => Timeline},
    Json0 = iolist_to_binary(json:encode(json_safe(Data))),
    Json = escape_script_json(Json0),
    Css =
      "<style>body{margin:0;background:#0f172a;color:#e2e8f0;font:14px ui-monospace,monospace}header,nav{padding:14px 18px;border-bottom:1px solid #334155}h1{font:600 20px system-ui;margin:0}button{background:#1e293b;color:#e2e8f0;border:1px solid #475569;border-radius:5px;padding:7px 10px;margin-right:7px}button.active{border-color:#34d399;color:#34d399}main{padding:18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111827;border:1px solid #334155;border-radius:6px;padding:12px}.muted{color:#94a3b8}</style>",
    Script =
      "<script>(()=>{'use strict';const d=JSON.parse(document.getElementById('beam-runtime-data').textContent);const out=document.getElementById('out');const buttons=[...document.querySelectorAll('button[data-view]')];function show(name){buttons.forEach(b=>b.classList.toggle('active',b.dataset.view===name));let v=name==='functions'?d.runtime.functions:name==='processes'?d.processes:name==='calls'?d.edges.call_edges:name==='messages'?d.edges.message_edges:name==='timeline'?d.timeline:d.runtime;out.textContent=JSON.stringify(v,null,2)}buttons.forEach(b=>b.onclick=()=>show(b.dataset.view));show('overlay')})();</script>",
    Html = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            "<title>Erlang BEAM Runtime Flow</title>", Css,
            "</head><body><header><h1>Runtime execution overlay</h1>",
            "<p class='muted'>Static certainty is preserved; runtime observations are additive.</p></header>",
            "<nav><button data-view='overlay'>Overlay</button><button data-view='functions'>Functions</button><button data-view='processes'>Processes</button><button data-view='calls'>Calls</button><button data-view='messages'>Messages</button><button data-view='timeline'>Timeline</button></nav>",
            "<main><pre id='out'></pre></main>",
            "<script id=\"beam-runtime-data\" type=\"application/json\">",
            Json, "</script>", Script, "</body></html>"],
    write_binary_exclusive(Path, unicode:characters_to_binary(Html)).

trace_raw_check(Input, MaximumFrameBytesText) ->
    MaximumFrameBytes = erlang:min(decimal_integer(MaximumFrameBytesText),
                                   67108864),
    true = MaximumFrameBytes > 0,
    {ok, Device} = file:open(Input, [read, raw, binary]),
    try
        Count = read_etf_frames(Device, MaximumFrameBytes, 1, 0),
        io:format("~tp.~n", [#{schema => beam_flow_raw_check_v1,
                                state => complete,
                                frame_count => Count,
                                maximum_frame_bytes => MaximumFrameBytes}])
    after
        ok = file:close(Device)
    end,
    ok.

read_etf_frames(Device, MaximumFrameBytes, Index, Count) ->
    case file:read(Device, 8) of
        eof -> Count;
        {ok, <<Length:64/unsigned-big>>} ->
            case Length > 0 andalso Length =< MaximumFrameBytes of
                true -> ok;
                false -> error({invalid_etf_frame_length, Index, Length,
                                MaximumFrameBytes})
            end,
            case file:read(Device, Length) of
                {ok, Payload} when byte_size(Payload) =:= Length ->
                    case Payload of
                        <<131, _/binary>> -> ok;
                        _ -> error({invalid_etf_frame_payload, Index})
                    end,
                    read_etf_frames(Device, MaximumFrameBytes,
                                    Index + 1, Count + 1);
                {ok, Payload} ->
                    error({truncated_etf_frame, Index, Length,
                           byte_size(Payload)});
                eof ->
                    error({truncated_etf_frame, Index, Length, 0});
                {error, Reason} ->
                    error({etf_frame_read_failed, Index, Reason})
            end;
        {ok, Header} ->
            error({truncated_etf_frame_header, Index, byte_size(Header)});
        {error, Reason} ->
            error({etf_frame_header_read_failed, Index, Reason})
    end.

peer_runtime_value(Result, Key) ->
    maps:get(Key, maps:get(runtime, Result, #{}), unknown).

isolation_atom("auto") -> auto;
isolation_atom("namespace") -> namespace;
isolation_atom("process") -> process;
isolation_atom(Other) -> error({invalid_isolation, Other}).

isolated_module_specs(ModuleRecords) ->
    [isolated_module_spec(Record) || Record <- ModuleRecords].

isolated_module_spec(Record) ->
    Module = maps:get(module, Record),
    Path = maps:get(beam_path, Record),
    ExpectedSha = maps:get(sha256, Record),
    ExpectedSha = sha256_hex(Path),
    Binary = read_binary(Path),
    #{module => Module,
      beam_path => Path,
      binary => Binary,
      sha256 => ExpectedSha,
      on_load => on_load_mfas(Module, Binary)}.

on_load_mfas(Module, Binary) ->
    {beam_file, Module, _Exports, Attributes, _CompileInfo, Functions} =
        beam_disasm:file(Binary),
    AttributeMFAs = case proplists:get_value(on_load, Attributes, []) of
        {Function, Arity} when is_atom(Function), is_integer(Arity) ->
            [{Module, Function, Arity}];
        Values when is_list(Values) ->
            [{Module, Function, Arity}
             || {Function, Arity} <- Values,
                is_atom(Function), is_integer(Arity)];
        _ -> []
    end,
    InstructionMFAs = [{Module, Function, Arity}
                       || {function, Function, Arity, _Entry, Instructions}
                              <- Functions,
                          lists:member(on_load, Instructions)],
    lists:usort(AttributeMFAs ++ InstructionMFAs).

declared_on_load_modules(ModuleSpecs) ->
    lists:usort([Module || #{module := Module, on_load := MFAs} <- ModuleSpecs,
                           MFAs =/= []]).

validate_scenario_modules(Scenario, ModuleSpecs) ->
    Supplied = [maps:get(module, Spec) || Spec <- ModuleSpecs],
    Requested = lists:usort(lists:filtermap(
      fun(#{op := load, module := Module}) -> {true, Module};
         (#{op := call, mfa := {Module, _, _}}) -> {true, Module};
         (#{op := spawn, mfa := {Module, _, _}}) -> {true, Module};
         (_) -> false
      end, maps:get(steps, Scenario))),
    Missing = Requested -- Supplied,
    case Missing of
        [] -> ok;
        _ -> error({scenario_modules_not_in_graph, Missing})
    end.

scenario_check(ScenarioPath) ->
    Scenario = consult_one(ScenarioPath),
    Steps = validate_scenario(Scenario),
    Timeout = maps:get(timeout_ms, Scenario),
    io:format("~tp.~n", [#{schema => beam_flow_scenario_v1,
                            state => valid,
                            step_count => length(Steps),
                            timeout_ms => Timeout}]),
    ok.

validate_scenario(Scenario) when is_map(Scenario) ->
    beam_flow_scenario_v1 = maps:get(schema, Scenario),
    require_exact_keys(Scenario, [schema, steps, timeout_ms]),
    Timeout = maps:get(timeout_ms, Scenario),
    require_positive_integer(timeout_ms, Timeout),
    Steps = maps:get(steps, Scenario),
    case is_list(Steps) of
        true -> ok;
        false -> error({invalid_scenario_steps, Steps})
    end,
    {_Bindings, _Stopped} = lists:foldl(
      fun validate_scenario_step/2, {#{}, false}, Steps),
    Steps;
validate_scenario(Other) ->
    error({invalid_scenario, Other}).

validate_scenario_step(_Step, {_Bindings, true}) ->
    error(scenario_step_after_stop);
validate_scenario_step(Step, {Bindings, false}) when is_map(Step) ->
    Op = maps:get(op, Step, missing),
    case Op of
        load ->
            require_exact_keys(Step, [module, op]),
            require_atom(module, maps:get(module, Step)),
            {Bindings, false};
        call ->
            validate_call_or_spawn(Step, call, Bindings);
        spawn ->
            validate_call_or_spawn(Step, spawn, Bindings);
        send ->
            require_exact_keys(Step, [message, op, target]),
            validate_bound_values([maps:get(target, Step),
                                   maps:get(message, Step)], Bindings),
            {Bindings, false};
        await ->
            require_exact_keys(Step, [op, pattern, timeout_ms]),
            require_positive_integer(timeout_ms, maps:get(timeout_ms, Step)),
            validate_bound_values([maps:get(pattern, Step)], Bindings),
            {Bindings, false};
        sleep ->
            require_exact_keys(Step, [duration_ms, op]),
            require_positive_integer(duration_ms, maps:get(duration_ms, Step)),
            {Bindings, false};
        assert ->
            require_exact_keys(Step, [equals, op, value]),
            validate_bound_values([maps:get(value, Step),
                                   maps:get(equals, Step)], Bindings),
            {Bindings, false};
        stop ->
            require_exact_keys(Step, [op]),
            {Bindings, true};
        missing ->
            error({missing_scenario_operation, Step});
        Other ->
            error({unsupported_scenario_operation, Other})
    end;
validate_scenario_step(Other, _State) ->
    error({invalid_scenario_step, Other}).

validate_call_or_spawn(Step, _Op, Bindings) ->
    Allowed = case maps:is_key(bind, Step) of
        true -> [args, bind, mfa, op];
        false -> [args, mfa, op]
    end,
    require_exact_keys(Step, Allowed),
    {Module, Function, Arity} = validate_mfa(maps:get(mfa, Step)),
    Args = maps:get(args, Step),
    case is_list(Args) andalso length(Args) =:= Arity of
        true -> ok;
        false -> error({scenario_arity_mismatch,
                        {Module, Function, Arity}, Args})
    end,
    validate_bound_values(Args, Bindings),
    case maps:find(bind, Step) of
        error -> {Bindings, false};
        {ok, Name} when is_atom(Name) ->
            case maps:is_key(Name, Bindings) of
                true -> error({duplicate_scenario_binding, Name});
                false -> {Bindings#{Name => declared}, false}
            end;
        {ok, Other} -> error({invalid_scenario_binding, Other})
    end.

validate_mfa({Module, Function, Arity})
  when is_atom(Module), is_atom(Function), is_integer(Arity), Arity >= 0 ->
    {Module, Function, Arity};
validate_mfa(Other) ->
    error({invalid_scenario_mfa, Other}).

validate_bound_values(Values, Bindings) ->
    lists:foreach(fun(Value) -> validate_bound_value(Value, Bindings) end,
                  Values).

validate_bound_value({binding, Name}, Bindings) when is_atom(Name) ->
    case maps:is_key(Name, Bindings) of
        true -> ok;
        false -> error({undefined_scenario_binding, Name})
    end;
validate_bound_value({self}, _Bindings) -> ok;
validate_bound_value(Tuple, Bindings) when is_tuple(Tuple) ->
    validate_bound_values(tuple_to_list(Tuple), Bindings);
validate_bound_value(List, Bindings) when is_list(List) ->
    validate_bound_values(List, Bindings);
validate_bound_value(Map, Bindings) when is_map(Map) ->
    validate_bound_values(maps:keys(Map) ++ maps:values(Map), Bindings);
validate_bound_value(_Literal, _Bindings) -> ok.

require_exact_keys(Map, Expected) ->
    Actual = lists:sort(maps:keys(Map)),
    case Actual =:= lists:sort(Expected) of
        true -> ok;
        false -> error({invalid_scenario_keys,
                        #{expected => lists:sort(Expected), actual => Actual}})
    end.

require_positive_integer(_Name, Value) when is_integer(Value), Value > 0 -> ok;
require_positive_integer(Name, Value) -> error({invalid_positive_integer, Name, Value}).

require_atom(_Name, Value) when is_atom(Value) -> ok;
require_atom(Name, Value) -> error({invalid_atom, Name, Value}).

decimal_integer(Text) ->
    try list_to_integer(Text)
    catch error:badarg -> error({invalid_decimal_integer, Text})
    end.

getenv_required(Name) ->
    case os:getenv(Name) of false -> error({missing_environment, Name}); Value -> Value end.

consult_one(Path) ->
    {ok, [Term]} = file:consult(Path),
    Term.

write_term_exclusive(Path, Term) -> write_binary_exclusive(Path, unicode:characters_to_binary(io_lib:format("~tp.~n", [Term]))).

write_binary_exclusive(Path, Binary) ->
    {ok, Io} = file:open(Path, [write, exclusive, binary]),
    try ok = file:write(Io, Binary) after ok = file:close(Io) end,
    ok.

copy_exclusive(Source, Destination) ->
    {ok, In} = file:open(Source, [read, binary, raw]),
    {ok, Out} = file:open(Destination, [write, exclusive, binary, raw]),
    try copy_loop(In, Out) after ok = file:close(In), ok = file:close(Out) end,
    ok.

copy_loop(In, Out) ->
    case file:read(In, 65536) of eof -> ok; {ok, Data} -> ok = file:write(Out, Data), copy_loop(In, Out) end.

sha256_hex(Path) -> hex(crypto:hash(sha256, read_binary(Path))).
md5_hex(Path) -> hex(crypto:hash(md5, read_binary(Path))).
read_binary(Path) -> {ok, Binary} = file:read_file(Path), Binary.
hex(Binary) -> lists:flatten([io_lib:format("~2.16.0b", [Byte]) || <<Byte>> <= Binary]).
ESCRIPT
}

runtime_agent_source() {
  cat <<'ERLANG'
-module(beam_flow_runtime_agent).
-export([run/4, live_run/8, stop_live/2]).

-define(LIVE_CONTROL_TABLE, beam_flow_runtime_agent_control).

run(Scenario, ModuleSpecs, _Options, RuntimePatterns) ->
    ModuleMap = maps:from_list(
      [{maps:get(module, Spec), Spec} || Spec <- ModuleSpecs]),
    Collector = spawn(fun() -> collector_loop([]) end),
    SessionName = list_to_atom(
      "beam_flow_trace_" ++
      integer_to_list(erlang:unique_integer([positive, monotonic]))),
    Session = start_trace_session(SessionName, Collector),
    MatchSpec = [{'_', [], [{return_trace}, {exception_trace}]}],
    FunctionMatchCounts = [
        {Pattern, safe_call(fun() ->
             trace:function(Session, Pattern, MatchSpec, [local])
         end)}
        || Pattern <- RuntimePatterns],
    0 = trace:function(Session, on_load, MatchSpec, [meta]),
    Parent = self(),
    {Runner, RunnerMonitor} = spawn_monitor(fun() ->
        receive
            {beam_flow_execute, Parent} ->
                scenario_runner(Parent, Scenario, ModuleMap)
        end
    end),
    1 = trace:process(Session, Runner, true,
                      [call, procs, set_on_spawn, send, 'receive',
                       monotonic_timestamp]),
    Runner ! {beam_flow_execute, Parent},
    Timeout = maps:get(timeout_ms, Scenario),
    ScenarioReport = await_scenario(Runner, RunnerMonitor, Timeout),
    TraceCleanup = drain_and_destroy(Session, 5000),
    DeliveryConfirmed = maps:get(delivery_confirmed, TraceCleanup),
    TraceDestroyed = maps:get(trace_session_destroyed, TraceCleanup),
    Events0 = collector_take(Collector),
    Collector ! stop,
    TraceEvents = [normalize_event(Raw, Sequence)
                   || {Raw, Sequence} <- lists:zip(
                        Events0, lists:seq(1, length(Events0)))],
    Declared = declared_on_load(ModuleSpecs),
    LoadedModules = maps:get(loaded_modules, ScenarioReport, []),
    Invoked = invoked_on_load(Declared, LoadedModules),
    OnLoadEvents = on_load_evidence_events(
      Declared, Invoked, TraceEvents, length(TraceEvents) + 1),
    Events = TraceEvents ++ OnLoadEvents,
    Complete = maps:get(status, ScenarioReport) =:= passed andalso
               DeliveryConfirmed andalso TraceDestroyed,
    #{schema => beam_flow_runtime_result_v1,
      state => case Complete of true -> complete; false -> partial end,
      runtime => #{otp_release => erlang:system_info(otp_release),
                   erts_version => erlang:system_info(version)},
      scenario => ScenarioReport,
      on_load => #{declared => lists:usort([M || {M, _, _} <- Declared]),
                   invoked => Invoked,
                   evidence => successful_code_load},
      instrumentation => #{function_patterns => RuntimePatterns,
                           function_match_counts => FunctionMatchCounts},
      trace_cleanup => TraceCleanup,
      events => Events}.

start_trace_session(Name, Tracer) ->
    trace:session_create(Name, Tracer, []).

drain_and_destroy(Session, Timeout) ->
    DeliveryReference = trace:delivered(Session, all),
    DeliveryConfirmed = receive
        {trace_delivered, _Tracee, DeliveryReference} -> true
    after Timeout ->
        false
    end,
    Destroyed = trace:session_destroy(Session) =:= true,
    SessionsAfter = trace:session_info(all),
    WeakSession = session_weak_reference(Session),
    CleanupConfirmed = Destroyed andalso
                       not lists:member(WeakSession, SessionsAfter),
    #{trace_session_destroyed => CleanupConfirmed,
      session_destroy_returned_true => Destroyed,
      owned_session_present_after_destroy =>
          lists:member(WeakSession, SessionsAfter),
      sessions_after_destroy => length(SessionsAfter),
      delivery_confirmed => DeliveryConfirmed}.

session_weak_reference({_Strong, Weak}) -> Weak;
session_weak_reference(Weak) -> Weak.

live_run(ModuleNames, ProcessSelectors, FunctionPatterns, EventSelectors,
         Limits, Backend, RunId, Controller) ->
    true = is_reference(RunId),
    true = is_pid(Controller),
    ?LIVE_CONTROL_TABLE = ets:new(
      ?LIVE_CONTROL_TABLE, [named_table, public, set,
                            {read_concurrency, true}]),
    true = ets:insert(?LIVE_CONTROL_TABLE, {RunId, self()}),
    ControllerMonitor = erlang:monitor(process, Controller),
    try
        live_run_owned(ModuleNames, ProcessSelectors, FunctionPatterns,
                       EventSelectors, Limits, Backend, ControllerMonitor)
    after
        erlang:demonitor(ControllerMonitor, [flush]),
        safe_call(fun() -> ets:delete(?LIVE_CONTROL_TABLE) end)
    end.

stop_live(RunId, Reason) when Reason =:= signal_int;
                              Reason =:= signal_term ->
    case ets:whereis(?LIVE_CONTROL_TABLE) of
        undefined -> {error, not_running};
        _ ->
            case ets:lookup(?LIVE_CONTROL_TABLE, RunId) of
                [{RunId, Owner}] when is_pid(Owner) ->
                    Owner ! {beam_flow_external_stop, Reason},
                    ok;
                [] -> {error, not_running}
            end
    end;
stop_live(_RunId, Reason) -> {error, {invalid_stop_reason, Reason}}.

live_run_owned(ModuleNames, ProcessSelectors, FunctionPatterns,
               EventSelectors, Limits, Backend, ControllerMonitor) ->
    Owner = self(),
    Collector = spawn(fun() ->
        live_collector_loop(Owner, Limits, [], 0, 0, none)
    end),
    CollectorMonitor = erlang:monitor(process, Collector),
    BackendState0 = start_live_backend(Backend, Collector),
    {TraceRun, BackendState} = try
        {Arming, ArmedBackendState} = arm_live_backend(
          BackendState0, Collector, ProcessSelectors, FunctionPatterns,
          EventSelectors),
        DurationMs = maps:get(duration_ms, Limits),
        {StopReason, TriggerTotals} = wait_live_stop(
          Collector, DurationMs, ControllerMonitor),
        {{ok, Arming, StopReason, TriggerTotals}, ArmedBackendState}
    catch
        Class:Reason:Stack ->
            {{error, {Class, Reason, Stack}}, BackendState0}
    end,
    TraceCleanup = cleanup_live_backend(BackendState, 5000),
    Capture = live_collector_take(Collector),
    Collector ! stop,
    CollectorStopped = receive
        {'DOWN', CollectorMonitor, process, Collector, _} -> true
    after 5000 ->
        false
    end,
    true = CollectorStopped,
    RawEvents = maps:get(events, Capture),
    Events = [normalize_event(Raw, Sequence)
              || {Raw, Sequence} <- lists:zip(
                   RawEvents, lists:seq(1, length(RawEvents)))],
    CleanupConfirmed = maps:get(backend_cleanup_confirmed, TraceCleanup),
    case TraceRun of
        {ok, ArmingResult, StopReasonResult, TriggerTotalsResult} ->
            ExpectedStop = not lists:member(
              StopReasonResult, [signal_int, signal_term, controller_down]),
            #{schema => beam_flow_runtime_result_v1,
              state => case CleanupConfirmed andalso ExpectedStop of
                  true -> complete;
                  false -> partial
              end,
              runtime => #{otp_release => erlang:system_info(otp_release),
                           erts_version => erlang:system_info(version)},
              capture => #{stop_reason => StopReasonResult,
                           trigger_totals => TriggerTotalsResult,
                           final_totals => maps:get(totals, Capture),
                           module_names => ModuleNames,
                           arming => ArmingResult},
              on_load => #{declared => [], invoked => [],
                           evidence => not_applicable},
              trace_cleanup => TraceCleanup,
              events => Events};
        {error, Failure} ->
            error({live_trace_arming_failed, Failure, TraceCleanup})
    end.

start_live_backend(session, Collector) ->
    Name = list_to_atom(
      "beam_flow_live_" ++
      integer_to_list(erlang:unique_integer([positive, monotonic]))),
    #{backend => session,
      collector => Collector,
      session => start_trace_session(Name, Collector)};
start_live_backend(dbg, Collector) ->
    Name = list_to_atom(
      "beam_flow_dbg_" ++
      integer_to_list(erlang:unique_integer([positive, monotonic]))),
    DbgSession = dbg:session_create(Name),
    try
        {ok, Tracer} = dbg:session(DbgSession, fun() ->
            dbg:tracer(process, {fun live_dbg_handler/2, Collector})
        end),
        TraceSession = dbg_trace_session_handle(DbgSession),
        #{backend => dbg,
          collector => Collector,
          dbg_session => DbgSession,
          tracer => Tracer,
          trace_session => TraceSession}
    catch
        Class:Reason:Stack ->
            _ = safe_call(fun() -> dbg:session_destroy(DbgSession) end),
            erlang:raise(Class, Reason, Stack)
    end;
start_live_backend(legacy, Collector) ->
    #{backend => legacy, collector => Collector};
start_live_backend(Other, _Collector) ->
    error({unsupported_live_backend, Other}).

live_dbg_handler(Event, Collector) ->
    Collector ! Event,
    Collector.

dbg_trace_session_handle(DbgSession) ->
    case erlang:process_info(DbgSession, {dictionary, node()}) of
        {{dictionary, _Node}, {_Relay, _Tracer, TraceSession}} -> TraceSession;
        Other -> error({dbg_trace_session_unavailable, Other})
    end.

arm_live_backend(BackendState, Collector, ProcessSelectors,
                 FunctionPatterns, EventSelectors) ->
    MatchSpec = [{'_', [], [{return_trace}, {exception_trace}]}],
    ProcessTargets = resolve_live_processes(ProcessSelectors,
                                            [self(), Collector]),
    ProcessFlags = live_process_flags(EventSelectors),
    case maps:get(backend, BackendState) of
        session ->
            Session = maps:get(session, BackendState),
            FunctionMatches = [
                trace:function(Session, Pattern, MatchSpec, [local])
                || Pattern <- FunctionPatterns],
            ProcessMatches = [
                trace:process(Session, Target, true, ProcessFlags)
                || Target <- ProcessTargets],
            Arming = live_arming_record(
              session, ProcessTargets, ProcessMatches, FunctionPatterns,
              FunctionMatches, ProcessFlags),
            {Arming, BackendState#{process_targets => ProcessTargets,
                                   function_patterns => FunctionPatterns}};
        dbg ->
            DbgSession = maps:get(dbg_session, BackendState),
            {FunctionMatches, ProcessMatches} = dbg:session(
              DbgSession, fun() ->
                  FMatches = [dbg:tpl(Pattern, MatchSpec)
                              || Pattern <- FunctionPatterns],
                  PMatches = [dbg:p(Target, ProcessFlags)
                              || Target <- ProcessTargets],
                  {FMatches, PMatches}
              end),
            Arming = live_arming_record(
              dbg, ProcessTargets, ProcessMatches, FunctionPatterns,
              FunctionMatches, ProcessFlags),
            {Arming, BackendState#{process_targets => ProcessTargets,
                                   function_patterns => FunctionPatterns}};
        legacy ->
            arm_legacy_backend(BackendState, MatchSpec, ProcessTargets,
                               FunctionPatterns, ProcessFlags)
    end.

live_arming_record(Backend, ProcessTargets, ProcessMatches,
                   FunctionPatterns, FunctionMatches, ProcessFlags) ->
    #{backend => Backend,
      process_targets => portable_term(ProcessTargets),
      process_match_counts => ProcessMatches,
      function_patterns => FunctionPatterns,
      function_match_counts => FunctionMatches,
      process_flags => ProcessFlags}.

cleanup_live_backend(#{backend := session, session := Session} = State,
                     Timeout) ->
    Disarm = disarm_trace_session(State),
    Cleanup0 = drain_and_destroy(Session, Timeout),
    Confirmed = maps:get(trace_session_destroyed, Cleanup0) andalso
                maps:get(delivery_confirmed, Cleanup0),
    Cleanup0#{backend => session,
              disarm => Disarm,
              backend_cleanup_confirmed => Confirmed};
cleanup_live_backend(#{backend := dbg} = State, Timeout) ->
    cleanup_dbg_backend(State, Timeout);
cleanup_live_backend(#{backend := legacy} = State, Timeout) ->
    cleanup_legacy_backend(State, Timeout).

disarm_trace_session(State) ->
    Session = maps:get(session, State),
    ProcessResults = [safe_call(fun() ->
                          trace:process(Session, Target, false, [all])
                      end)
                      || Target <- maps:get(process_targets, State, [])],
    FunctionResults = [safe_call(fun() -> trace:function(
                         Session, Pattern, false, [local]) end)
                       || Pattern <- maps:get(function_patterns, State, [])],
    #{process_results => ProcessResults,
      function_results => FunctionResults}.

cleanup_dbg_backend(State, Timeout) ->
    DbgSession = maps:get(dbg_session, State),
    TraceSession = maps:get(trace_session, State),
    Tracer = maps:get(tracer, State),
    Disarm = safe_call(fun() -> dbg:session(DbgSession, fun() ->
        ProcessResults = [safe_call(fun() -> dbg:p(Target, clear) end)
                          || Target <- maps:get(process_targets, State, [])],
        FunctionResults = [safe_call(fun() -> dbg:ctpl(Pattern) end)
                           || Pattern <- maps:get(function_patterns, State, [])],
        #{process_results => ProcessResults,
          function_results => FunctionResults}
    end) end),
    DeliveryConfirmed = trace_delivery_barrier(TraceSession, Timeout),
    DbgMonitor = erlang:monitor(process, DbgSession),
    TracerMonitor = erlang:monitor(process, Tracer),
    DestroyResult = safe_call(fun() -> dbg:session_destroy(DbgSession) end),
    DbgStopped = wait_monitor_down(DbgMonitor, DbgSession, Timeout),
    TracerStopped = wait_monitor_down(TracerMonitor, Tracer, Timeout),
    WeakSession = session_weak_reference(TraceSession),
    SessionsAfterDbg = trace:session_info(all),
    PresentAfterDbg = lists:member(WeakSession, SessionsAfterDbg),
    DirectDestroyResult = case PresentAfterDbg of
        true -> safe_call(fun() -> trace:session_destroy(TraceSession) end);
        false -> not_needed
    end,
    SessionsAfter = trace:session_info(all),
    SessionPresent = lists:member(WeakSession, SessionsAfter),
    Confirmed = DestroyResult =:= ok andalso DbgStopped andalso
                TracerStopped andalso not SessionPresent andalso
                DeliveryConfirmed,
    #{backend => dbg,
      disarm => portable_term(Disarm),
      delivery_confirmed => DeliveryConfirmed,
      trace_session_destroyed => not SessionPresent,
      owned_session_present_after_destroy => SessionPresent,
      sessions_after_destroy => length(SessionsAfter),
      dbg_session_destroyed => DbgStopped,
      dbg_tracer_stopped => TracerStopped,
      dbg_destroy_result => DestroyResult,
      dbg_left_trace_session => PresentAfterDbg,
      direct_trace_session_destroy_result => DirectDestroyResult,
      backend_cleanup_confirmed => Confirmed}.

trace_delivery_barrier(Session, Timeout) ->
    Reference = trace:delivered(Session, all),
    receive
        {trace_delivered, _Tracee, Reference} -> true
    after Timeout -> false
    end.

wait_monitor_down(Monitor, Pid, Timeout) ->
    receive
        {'DOWN', Monitor, process, Pid, _} -> true
    after Timeout ->
        erlang:demonitor(Monitor, [flush]),
        not is_process_alive(Pid)
    end.

arm_legacy_backend(BackendState, MatchSpec, ProcessTargets,
                   FunctionPatterns, ProcessFlags) ->
    true = lists:all(fun is_exact_mfa/1, FunctionPatterns),
    Snapshot = #{processes => [legacy_process_state(Target)
                               || Target <- ProcessTargets],
                 functions => [legacy_function_state(Pattern)
                               || Pattern <- FunctionPatterns]},
    State = BackendState#{legacy_snapshot => Snapshot,
                          legacy_match_spec => MatchSpec,
                          process_targets => ProcessTargets,
                          function_patterns => FunctionPatterns},
    try
        ProcessPreclear = [legacy_clear_process(Target)
                           || Target <- ProcessTargets],
        FunctionMatches = [erlang:trace_pattern(
                             Pattern, MatchSpec, [local])
                           || Pattern <- FunctionPatterns],
        ProcessMatches = [erlang:trace(
                            Target, true,
                            [{tracer, maps:get(collector, BackendState)} |
                             ProcessFlags])
                          || Target <- ProcessTargets],
        Arming = live_arming_record(
          legacy, ProcessTargets, ProcessMatches, FunctionPatterns,
          FunctionMatches, ProcessFlags),
        ArmingWithSnapshot = Arming#{legacy_process_preclear =>
                                        portable_term(ProcessPreclear)},
        {ArmingWithSnapshot, State}
    catch
        Class:Reason:Stack ->
            Cleanup = cleanup_legacy_backend(State, 5000),
            error({legacy_arming_failed, {Class, Reason, Stack}, Cleanup})
    end.

is_exact_mfa({Module, Function, Arity}) ->
    is_atom(Module) andalso Module =/= '_' andalso
    is_atom(Function) andalso Function =/= '_' andalso
    is_integer(Arity) andalso Arity >= 0;
is_exact_mfa(_) -> false.

legacy_process_state(Target) ->
    #{target => Target,
      flags => legacy_trace_info(Target, flags),
      tracer => legacy_trace_info(Target, tracer)}.

legacy_function_state(MFA) ->
    #{mfa => MFA,
      traced => legacy_trace_info(MFA, traced),
      match_spec => legacy_trace_info(MFA, match_spec)}.

legacy_trace_info(Target, Item) ->
    case erlang:trace_info(Target, Item) of
        {Item, Value} -> Value;
        undefined -> undefined
    end.

cleanup_legacy_backend(#{legacy_snapshot := Snapshot} = State, Timeout) ->
    Collector = maps:get(collector, State),
    MatchSpec = maps:get(legacy_match_spec, State),
    ProcessStates = maps:get(processes, Snapshot),
    FunctionStates = maps:get(functions, Snapshot),
    ProcessConflicts = [Conflict
                        || ProcessState <- ProcessStates,
                           Conflict <- legacy_process_conflict(
                             ProcessState, Collector)],
    FunctionConflicts = [Conflict
                         || FunctionState <- FunctionStates,
                            Conflict <- legacy_function_conflict(
                              FunctionState, MatchSpec)],
    ConflictTargets = [maps:get(target, Conflict)
                       || Conflict <- ProcessConflicts],
    ConflictMFAs = [maps:get(mfa, Conflict)
                    || Conflict <- FunctionConflicts],
    SafeProcessStates = [Entry || Entry <- ProcessStates,
                                  not lists:member(maps:get(target, Entry),
                                                   ConflictTargets)],
    SafeFunctionStates = [Entry || Entry <- FunctionStates,
                                   not lists:member(maps:get(mfa, Entry),
                                                    ConflictMFAs)],
    OwnedProcesses = legacy_owned_processes(Collector),
    SnapshotTargets = [maps:get(target, Entry)
                       || Entry <- SafeProcessStates],
    ClearTargets = lists:usort(OwnedProcesses ++ SnapshotTargets),
    ClearProcessResults = [legacy_clear_process(Target)
                           || Target <- ClearTargets],
    ClearFunctionResults = [legacy_clear_function(
                              maps:get(mfa, Entry), MatchSpec)
                            || Entry <- SafeFunctionStates],
    DeliveryConfirmed = legacy_delivery_barrier(Timeout),
    ProcessRestore = [legacy_restore_process(Entry)
                      || Entry <- SafeProcessStates],
    FunctionRestore = [legacy_restore_function(Entry)
                       || Entry <- SafeFunctionStates],
    ProcessVerified = lists:all(fun legacy_process_restored/1,
                                ProcessStates),
    FunctionVerified = lists:all(fun legacy_function_restored/1,
                                 FunctionStates),
    OwnedRemain = legacy_owned_processes(Collector),
    StateRestored = ProcessConflicts =:= [] andalso
                    FunctionConflicts =:= [] andalso
                    ProcessVerified andalso FunctionVerified andalso
                    OwnedRemain =:= [],
    Confirmed = DeliveryConfirmed andalso StateRestored,
    #{backend => legacy,
      delivery_confirmed => DeliveryConfirmed,
      trace_session_destroyed => Confirmed,
      owned_session_present_after_destroy => false,
      backend_cleanup_confirmed => Confirmed,
      legacy_state_restored => StateRestored,
      legacy_snapshot_counts => #{processes => length(ProcessStates),
                                  functions => length(FunctionStates)},
      legacy_process_conflicts => portable_term(ProcessConflicts),
      legacy_function_conflicts => portable_term(FunctionConflicts),
      legacy_owned_processes_after => portable_term(OwnedRemain),
      legacy_clear_process_results => portable_term(ClearProcessResults),
      legacy_clear_function_results => portable_term(ClearFunctionResults),
      legacy_process_restore_results => portable_term(ProcessRestore),
      legacy_function_restore_results => portable_term(FunctionRestore),
      manual_cleanup => legacy_manual_cleanup(
        ClearTargets, [maps:get(mfa, Entry) || Entry <- FunctionStates])};
cleanup_legacy_backend(#{backend := legacy}, _Timeout) ->
    #{backend => legacy,
      delivery_confirmed => true,
      trace_session_destroyed => true,
      owned_session_present_after_destroy => false,
      backend_cleanup_confirmed => true,
      legacy_state_restored => true,
      legacy_snapshot_counts => #{processes => 0, functions => 0},
      manual_cleanup => []}.

legacy_process_conflict(#{target := Target, flags := OriginalFlags,
                          tracer := OriginalTracer}, Collector) ->
    case legacy_current_process_state(Target) of
        dead -> [];
        #{flags := _CurrentFlags, tracer := CurrentTracer}
          when CurrentTracer =:= Collector -> [];
        #{flags := OriginalFlags, tracer := OriginalTracer} -> [];
        Current -> [#{target => Target, original_flags => OriginalFlags,
                      original_tracer => OriginalTracer,
                      current => Current}]
    end.

legacy_function_conflict(#{mfa := MFA, traced := OriginalTraced,
                           match_spec := OriginalMatchSpec}, MatchSpec) ->
    Current = legacy_current_function_state(MFA),
    case Current of
        #{traced := local, match_spec := MatchSpec} -> [];
        #{traced := OriginalTraced, match_spec := OriginalMatchSpec} -> [];
        _ -> [#{mfa => MFA, original_traced => OriginalTraced,
                original_match_spec => OriginalMatchSpec,
                current => Current}]
    end.

legacy_current_process_state(Target) ->
    try
        Flags = legacy_trace_info(Target, flags),
        Tracer = legacy_trace_info(Target, tracer),
        case Flags =:= undefined orelse Tracer =:= undefined of
            true -> dead;
            false -> #{flags => Flags, tracer => Tracer}
        end
    catch error:badarg -> dead
    end.

legacy_current_function_state(MFA) ->
    #{traced => legacy_trace_info(MFA, traced),
      match_spec => legacy_trace_info(MFA, match_spec)}.

legacy_owned_processes(Collector) ->
    Candidates = [new | processes()],
    [Target || Target <- Candidates,
               case legacy_current_process_state(Target) of
                   #{tracer := Collector} -> true;
                   _ -> false
               end].

legacy_clear_process(Target) ->
    try {Target, erlang:trace(Target, false, [all])}
    catch error:badarg -> {Target, dead}
    end.

legacy_clear_function(MFA, MatchSpec) ->
    case legacy_current_function_state(MFA) of
        #{traced := local, match_spec := MatchSpec} ->
            {MFA, erlang:trace_pattern(MFA, false, [local])};
        Current -> {MFA, unchanged, Current}
    end.

legacy_delivery_barrier(Timeout) ->
    Reference = erlang:trace_delivered(all),
    receive
        {trace_delivered, _Tracee, Reference} -> true
    after Timeout -> false
    end.

legacy_restore_process(#{target := Target, flags := Flags,
                         tracer := Tracer}) ->
    case legacy_current_process_state(Target) of
        dead -> {Target, dead};
        _ ->
            _ = erlang:trace(Target, false, [all]),
            case Flags of
                [] -> {Target, restored_empty};
                undefined -> {Target, dead};
                _ ->
                    Options = case Tracer of
                        [] -> Flags;
                        undefined -> Flags;
                        _ -> [{tracer, Tracer} | Flags]
                    end,
                    {Target, erlang:trace(Target, true, Options)}
            end
    end.

legacy_restore_function(#{mfa := MFA, traced := false}) ->
    {MFA, restored_false};
legacy_restore_function(#{mfa := MFA, traced := local,
                          match_spec := MatchSpec}) ->
    {MFA, erlang:trace_pattern(MFA, MatchSpec, [local])};
legacy_restore_function(#{mfa := MFA, traced := global,
                          match_spec := MatchSpec}) ->
    {MFA, erlang:trace_pattern(MFA, MatchSpec, [])};
legacy_restore_function(#{mfa := MFA, traced := Traced}) ->
    {MFA, {unsupported_original_trace_kind, Traced}}.

safe_call(Function) when is_function(Function, 0) ->
    try Function()
    catch
        Class:Reason:Stack -> {'EXIT', {Class, Reason, Stack}}
    end.

legacy_process_restored(#{target := Target, flags := OriginalFlags,
                          tracer := OriginalTracer}) ->
    case legacy_current_process_state(Target) of
        dead -> is_pid(Target);
        #{flags := OriginalFlags, tracer := OriginalTracer} -> true;
        _ -> false
    end.

legacy_function_restored(#{mfa := MFA, traced := OriginalTraced,
                           match_spec := OriginalMatchSpec}) ->
    case legacy_current_function_state(MFA) of
        #{traced := OriginalTraced, match_spec := OriginalMatchSpec} -> true;
        _ -> false
    end.

legacy_manual_cleanup(Targets, MFAs) ->
    [#{module => erlang, function => trace,
       arguments => [portable_term(Target), false, [all]]}
     || Target <- Targets] ++
    [#{module => erlang, function => trace_pattern,
       arguments => [MFA, false, [local]]}
     || MFA <- MFAs].

resolve_live_processes([], _Owned) ->
    error(live_process_selector_required);
resolve_live_processes(Selectors, Owned) ->
    lists:usort(lists:append(
      [resolve_live_process_selector(Selector, Owned)
       || Selector <- Selectors])).

resolve_live_process_selector("all", Owned) ->
    [new | [Pid || Pid <- processes(), not lists:member(Pid, Owned)]];
resolve_live_process_selector("existing", Owned) ->
    [Pid || Pid <- processes(), not lists:member(Pid, Owned)];
resolve_live_process_selector("new", _Owned) -> [new];
resolve_live_process_selector("registered:" ++ NameText, Owned) ->
    Name = try list_to_existing_atom(NameText)
           catch error:badarg -> error({unknown_registered_process, NameText})
           end,
    case whereis(Name) of
        Pid when is_pid(Pid) ->
            case lists:member(Pid, Owned) of
                true -> error({refusing_owned_trace_process, NameText});
                false -> [Pid]
            end;
        undefined -> error({registered_process_not_found, NameText})
    end;
resolve_live_process_selector("pid:" ++ PidText, Owned) ->
    Pid = try list_to_pid(PidText)
          catch error:badarg -> error({invalid_live_pid, PidText})
          end,
    case node(Pid) =:= node() andalso is_process_alive(Pid) andalso
         not lists:member(Pid, Owned) of
        true -> [Pid];
        false -> error({live_pid_not_traceable, PidText})
    end;
resolve_live_process_selector(Other, _Owned) ->
    error({unsupported_live_process_selector, Other}).

live_process_flags([]) ->
    [call, procs, set_on_spawn, send, 'receive', monotonic_timestamp];
live_process_flags(Selectors) ->
    Expanded = lists:append([live_event_flags(Selector)
                             || Selector <- Selectors]),
    lists:usort([monotonic_timestamp | Expanded]).

live_event_flags("all") ->
    [call, procs, set_on_spawn, send, 'receive', garbage_collection, running];
live_event_flags("call") -> [call];
live_event_flags("return") -> [call];
live_event_flags("exception") -> [call];
live_event_flags("process") -> [procs, set_on_spawn];
live_event_flags("send") -> [send];
live_event_flags("receive") -> ['receive'];
live_event_flags("garbage_collection") -> [garbage_collection];
live_event_flags("scheduler") -> [running];
live_event_flags(Other) -> error({unsupported_live_event_selector, Other}).

wait_live_stop(Collector, infinity, ControllerMonitor) ->
    receive
        {beam_flow_limit, Collector, Reason, Totals} -> {Reason, Totals};
        {beam_flow_external_stop, Reason} ->
            {Reason, live_collector_snapshot(Collector)};
        {'DOWN', ControllerMonitor, process, _Controller, _Reason} ->
            {controller_down, live_collector_snapshot(Collector)}
    end;
wait_live_stop(Collector, DurationMs, ControllerMonitor) ->
    receive
        {beam_flow_limit, Collector, Reason, Totals} -> {Reason, Totals};
        {beam_flow_external_stop, Reason} ->
            {Reason, live_collector_snapshot(Collector)};
        {'DOWN', ControllerMonitor, process, _Controller, _Reason} ->
            {controller_down, live_collector_snapshot(Collector)}
    after DurationMs ->
        {duration, live_collector_snapshot(Collector)}
    end.

live_collector_snapshot(Collector) ->
    Reference = make_ref(),
    Collector ! {snapshot, self(), Reference},
    receive
        {live_snapshot, Reference, Totals} -> Totals
    after 1000 ->
        #{events => unknown, bytes => unknown}
    end.

live_collector_take(Collector) ->
    Reference = make_ref(),
    Collector ! {take_live, self(), Reference},
    receive
        {live_events, Reference, Capture} -> Capture
    after 5000 ->
        error(live_trace_collector_timeout)
    end.

live_collector_loop(Owner0, Limits, Events, Count, Bytes, Trigger) ->
    receive
        {snapshot, From, Reference} ->
            From ! {live_snapshot, Reference,
                    #{events => Count, bytes => Bytes}},
            live_collector_loop(Owner0, Limits, Events, Count, Bytes, Trigger);
        {take_live, From, Reference} ->
            {FinalEvents, FinalCount, FinalBytes, FinalTrigger} =
                live_collector_drain(Events, Count, Bytes, Trigger, Limits,
                                     Owner0),
            From ! {live_events, Reference,
                    #{events => lists:reverse(FinalEvents),
                      totals => #{events => FinalCount, bytes => FinalBytes},
                      trigger => FinalTrigger}},
            live_collector_loop(Owner0, Limits, [], 0, 0, FinalTrigger);
        stop -> ok;
        RawEvent ->
            {NewEvents, NewCount, NewBytes, NewTrigger} =
                retain_live_event(RawEvent, Events, Count, Bytes, Trigger,
                                  Limits, Owner0),
            live_collector_loop(Owner0, Limits, NewEvents, NewCount,
                                NewBytes, NewTrigger)
    end.

live_collector_drain(Events, Count, Bytes, Trigger, Limits, Owner) ->
    receive
        RawEvent ->
            {NewEvents, NewCount, NewBytes, NewTrigger} =
                retain_live_event(RawEvent, Events, Count, Bytes, Trigger,
                                  Limits, Owner),
            live_collector_drain(NewEvents, NewCount, NewBytes, NewTrigger,
                                 Limits, Owner)
    after 20 ->
        {Events, Count, Bytes, Trigger}
    end.

retain_live_event(RawEvent, Events, Count, Bytes, Trigger, Limits, Owner) ->
    Payload = term_to_binary(RawEvent, [compressed]),
    NewCount = Count + 1,
    NewBytes = Bytes + 8 + byte_size(Payload),
    Totals = #{events => NewCount, bytes => NewBytes},
    NewTrigger = case Trigger of
        none ->
            case live_stop_reason(Limits, Totals) of
                continue -> none;
                Reason ->
                    Owner ! {beam_flow_limit, self(), Reason, Totals},
                    #{reason => Reason, totals => Totals}
            end;
        Existing -> Existing
    end,
    {[RawEvent | Events], NewCount, NewBytes, NewTrigger}.

live_stop_reason(#{max_events := Maximum}, #{events := Count})
  when is_integer(Maximum), Count >= Maximum -> max_events;
live_stop_reason(#{max_bytes := Maximum}, #{bytes := Bytes})
  when is_integer(Maximum), Bytes >= Maximum -> max_bytes;
live_stop_reason(_Limits, _Totals) -> continue.

collector_loop(Events) ->
    receive
        {take, From, Reference} ->
            Complete = collector_drain(Events),
            From ! {events, Reference, lists:reverse(Complete)},
            collector_loop([]);
        stop ->
            ok;
        Event ->
            collector_loop([Event | Events])
    end.

collector_drain(Events) ->
    receive
        Event -> collector_drain([Event | Events])
    after 20 ->
        Events
    end.

collector_take(Collector) ->
    Reference = make_ref(),
    Collector ! {take, self(), Reference},
    receive
        {events, Reference, Events} -> Events
    after 5000 ->
        error(trace_collector_timeout)
    end.

await_scenario(Runner, RunnerMonitor, Timeout) ->
    receive
        {beam_flow_scenario_result, Runner, Report} ->
            await_runner_down(Runner, RunnerMonitor, Report);
        {'DOWN', RunnerMonitor, process, Runner, Reason} ->
            #{status => failed,
              step_count => 0,
              completed_steps => 0,
              assertions_passed => 0,
              reason => portable_term({runner_exit, Reason})}
    after Timeout ->
        exit(Runner, kill),
        receive
            {'DOWN', RunnerMonitor, process, Runner, _} -> ok
        after 1000 -> ok
        end,
        #{status => timeout,
          step_count => 0,
          completed_steps => 0,
          assertions_passed => 0,
          reason => scenario_timeout}
    end.

await_runner_down(Runner, RunnerMonitor, Report) ->
    receive
        {'DOWN', RunnerMonitor, process, Runner, normal} -> Report;
        {'DOWN', RunnerMonitor, process, Runner, Reason} ->
            Report#{status => failed,
                    reason => portable_term({runner_exit_after_result, Reason})}
    after 1000 ->
        exit(Runner, kill),
        Report#{status => failed, reason => runner_did_not_exit}
    end.

scenario_runner(Owner, Scenario, ModuleMap) ->
    Steps = maps:get(steps, Scenario),
    Deadline = erlang:monotonic_time(millisecond) +
               maps:get(timeout_ms, Scenario),
    Context0 = #{bindings => #{}, modules => ModuleMap,
                 loaded => #{}, deadline => Deadline},
    Report = try execute_steps(Steps, Context0, [], 0, 0) of
        {Context, Results, Completed, Assertions} ->
            _ = cleanup_owned_processes(Context),
            #{status => passed,
              step_count => length(Steps),
              completed_steps => Completed,
              assertions_passed => Assertions,
              loaded_modules => lists:sort(maps:keys(maps:get(loaded, Context))),
              results => portable_term(lists:reverse(Results))}
    catch
        Class:Reason:Stack ->
            _ = cleanup_owned_processes(Context0),
            #{status => failed,
              step_count => length(Steps),
              completed_steps => 0,
              assertions_passed => 0,
              reason => portable_term({Class, Reason, Stack})}
    end,
    Owner ! {beam_flow_scenario_result, self(), Report}.

execute_steps([], Context, Results, Completed, Assertions) ->
    {Context, Results, Completed, Assertions};
execute_steps([Step | Rest], Context0, Results, Completed, Assertions0) ->
    ensure_before_deadline(Context0),
    {Action, Context, Result, AssertionDelta} = execute_step(Step, Context0),
    case Action of
        continue -> execute_steps(Rest, Context, [Result | Results],
                                  Completed + 1,
                                  Assertions0 + AssertionDelta);
        stop -> {Context, [Result | Results], Completed + 1,
                 Assertions0 + AssertionDelta}
    end.

execute_step(#{op := load, module := Module}, Context0) ->
    {Status, Context} = load_target_module(Module, Context0),
    {continue, Context, #{op => load, module => Module, status => Status}, 0};
execute_step(#{op := call, mfa := {Module, Function, Arity}, args := Args} = Step,
             Context0) ->
    {_Status, Context1} = load_target_module(Module, Context0),
    ResolvedArgs = resolve_values(Args, Context1),
    Arity = length(ResolvedArgs),
    Value = apply(Module, Function, ResolvedArgs),
    Context = maybe_bind(Step, Value, Context1),
    {continue, Context,
     #{op => call, mfa => {Module, Function, Arity}, value => Value}, 0};
execute_step(#{op := spawn, mfa := {Module, Function, Arity}, args := Args} = Step,
             Context0) ->
    {_Status, Context1} = load_target_module(Module, Context0),
    ResolvedArgs = resolve_values(Args, Context1),
    Arity = length(ResolvedArgs),
    Pid = spawn(Module, Function, ResolvedArgs),
    Context = maybe_bind(Step, Pid, Context1),
    {continue, Context,
     #{op => spawn, mfa => {Module, Function, Arity}, pid => Pid}, 0};
execute_step(#{op := send, target := Target0, message := Message0}, Context) ->
    Target = resolve_value(Target0, Context),
    Message = resolve_value(Message0, Context),
    _ = Target ! Message,
    {continue, Context, #{op => send, target => Target,
                          message => Message}, 0};
execute_step(#{op := await, pattern := Pattern0,
               timeout_ms := RequestedTimeout}, Context) ->
    Pattern = resolve_value(Pattern0, Context),
    Timeout = erlang:min(RequestedTimeout, remaining_ms(Context)),
    case Timeout > 0 of
        true -> ok;
        false -> error(scenario_timeout)
    end,
    receive
        Pattern ->
            {continue, Context, #{op => await, matched => Pattern}, 0}
    after Timeout ->
        error({scenario_await_timeout, Pattern, Timeout})
    end;
execute_step(#{op := sleep, duration_ms := Duration}, Context) ->
    case Duration =< remaining_ms(Context) of
        true -> timer:sleep(Duration);
        false -> error({scenario_sleep_exceeds_deadline, Duration})
    end,
    {continue, Context, #{op => sleep, duration_ms => Duration}, 0};
execute_step(#{op := assert, value := Value0, equals := Expected0}, Context) ->
    Value = resolve_value(Value0, Context),
    Expected = resolve_value(Expected0, Context),
    case Value =:= Expected of
        true -> {continue, Context,
                 #{op => assert, status => passed,
                   value => Value, equals => Expected}, 1};
        false -> error({scenario_assertion_failed, Value, Expected})
    end;
execute_step(#{op := stop}, Context) ->
    Context1 = cleanup_owned_processes(Context),
    {stop, Context1, #{op => stop, status => complete}, 0}.

load_target_module(Module, Context = #{loaded := Loaded}) ->
    case maps:is_key(Module, Loaded) of
        true -> {already_loaded, Context};
        false ->
            Spec = maps:get(Module, maps:get(modules, Context)),
            Binary = maps:get(binary, Spec),
            BeamPath = maps:get(beam_path, Spec),
            case code:load_binary(Module, BeamPath, Binary) of
                {module, Module} ->
                    {loaded, Context#{loaded := Loaded#{Module => true}}};
                {error, Reason} ->
                    error({scenario_module_load_failed, Module, Reason})
            end
    end.

maybe_bind(Step, Value, Context = #{bindings := Bindings}) ->
    case maps:find(bind, Step) of
        error -> Context;
        {ok, Name} -> Context#{bindings := Bindings#{Name => Value}}
    end.

resolve_values(Values, Context) ->
    [resolve_value(Value, Context) || Value <- Values].

resolve_value({binding, Name}, #{bindings := Bindings}) ->
    maps:get(Name, Bindings);
resolve_value({self}, _Context) ->
    self();
resolve_value(Tuple, Context) when is_tuple(Tuple) ->
    list_to_tuple(resolve_values(tuple_to_list(Tuple), Context));
resolve_value(List, Context) when is_list(List) ->
    resolve_values(List, Context);
resolve_value(Map, Context) when is_map(Map) ->
    maps:from_list([{resolve_value(Key, Context), resolve_value(Value, Context)}
                    || {Key, Value} <- maps:to_list(Map)]);
resolve_value(Literal, _Context) ->
    Literal.

ensure_before_deadline(Context) ->
    case remaining_ms(Context) > 0 of
        true -> ok;
        false -> error(scenario_timeout)
    end.

remaining_ms(Context) ->
    maps:get(deadline, Context) - erlang:monotonic_time(millisecond).

cleanup_owned_processes(Context = #{bindings := Bindings}) ->
    Pids = lists:usort([Pid || Pid <- maps:values(Bindings), is_pid(Pid)]),
    lists:foreach(fun(Pid) ->
        case is_process_alive(Pid) of
            true -> Pid ! stop;
            false -> ok
        end
    end, Pids),
    wait_owned_processes(Pids, 500),
    Context.

wait_owned_processes([], _Timeout) -> ok;
wait_owned_processes(Pids, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Monitors = [{Pid, erlang:monitor(process, Pid)}
                || Pid <- Pids, is_process_alive(Pid)],
    wait_owned_monitors(Monitors, Deadline).

wait_owned_monitors([], _Deadline) -> ok;
wait_owned_monitors([{Pid, Reference} | Rest], Deadline) ->
    Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {'DOWN', Reference, process, Pid, _} ->
            wait_owned_monitors(Rest, Deadline)
    after Remaining ->
        exit(Pid, kill),
        receive
            {'DOWN', Reference, process, Pid, _} -> ok
        after 100 -> ok
        end,
        wait_owned_monitors(Rest, Deadline)
    end.

declared_on_load(ModuleSpecs) ->
    lists:usort(lists:append([maps:get(on_load, Spec, [])
                              || Spec <- ModuleSpecs])).

invoked_on_load(Declared, LoadedModules) ->
    lists:usort([Module || {Module, _, _} <- Declared,
                           lists:member(Module, LoadedModules)]).

on_load_evidence_events(Declared, Invoked, TraceEvents, FirstSequence) ->
    MFAs = [MFA || MFA = {Module, _, _} <- Declared,
                    lists:member(Module, Invoked)],
    [#{sequence => Sequence,
       kind => on_load,
       node => node(),
       pid => undefined,
       timestamp => undefined,
       mfa => MFA,
       evidence => successful_code_load,
       trace_call_observed => lists:any(fun(Event) ->
           maps:get(kind, Event) =:= call andalso
           maps:get(mfa, Event, undefined) =:= MFA
       end, TraceEvents),
       raw_etf_base64 => base64:encode(term_to_binary(
         {beam_flow_observation, on_load, MFA, successful_code_load},
         [compressed]))}
     || {MFA, Sequence} <- lists:zip(
          MFAs, lists:seq(FirstSequence,
                          FirstSequence + length(MFAs) - 1))].

normalize_event(Raw, Sequence) ->
    RawKind = trace_kind(Raw),
    Kind = normalized_trace_kind(RawKind),
    Base = #{sequence => Sequence,
             kind => Kind,
             node => node(),
             pid => trace_pid(Raw),
             timestamp => trace_timestamp(Raw),
             raw_etf_base64 => base64:encode(term_to_binary(Raw, [compressed]))},
    maps:merge(Base, trace_details(Kind, RawKind, Raw)).

trace_kind(Raw) when is_tuple(Raw), tuple_size(Raw) >= 3 ->
    case element(1, Raw) of
        trace -> element(3, Raw);
        trace_ts -> element(3, Raw);
        _ -> unknown
    end;
trace_kind(_) -> unknown.

normalized_trace_kind(in) -> scheduler_in;
normalized_trace_kind(out) -> scheduler_out;
normalized_trace_kind(in_exiting) -> scheduler_in_exiting;
normalized_trace_kind(out_exiting) -> scheduler_out_exiting;
normalized_trace_kind(out_exited) -> scheduler_out_exited;
normalized_trace_kind(Kind) ->
    Known = [call, return_from, return_to, exception_from,
             spawn, spawned, exit, register, unregister,
             link, unlink, getting_linked, getting_unlinked,
             send, send_to_non_existing_process, 'receive',
             gc_start, gc_end, gc_minor_start, gc_minor_end,
             gc_major_start, gc_major_end, gc_max_heap_size,
             open, closed],
    case lists:member(Kind, Known) of
        true -> Kind;
        false -> unknown_runtime_event
    end.

trace_pid(Raw) when is_tuple(Raw), tuple_size(Raw) >= 2 ->
    portable_term(element(2, Raw));
trace_pid(_) -> undefined.

trace_timestamp(Raw) when is_tuple(Raw), tuple_size(Raw) >= 1 ->
    case element(1, Raw) of
        trace_ts -> portable_term(element(tuple_size(Raw), Raw));
        _ -> undefined
    end;
trace_timestamp(_) -> undefined.

trace_details(call, _RawKind, Raw) ->
    case element(4, Raw) of
        {Module, Function, Args} when is_list(Args) ->
            #{mfa => {Module, Function, length(Args)},
              arguments => portable_term(Args)};
        {Module, Function, Arity} ->
            #{mfa => {Module, Function, Arity}};
        Other -> #{detail => portable_term(Other)}
    end;
trace_details(return_from, _RawKind, Raw) ->
    #{mfa => element(4, Raw), return_value => portable_term(element(5, Raw))};
trace_details(return_to, _RawKind, Raw) ->
    #{mfa => element(4, Raw)};
trace_details(exception_from, _RawKind, Raw) ->
    #{mfa => element(4, Raw), exception => portable_term(element(5, Raw))};
trace_details(spawn, _RawKind, Raw) ->
    #{child => portable_term(element(4, Raw)),
      entry => portable_term(element(5, Raw))};
trace_details(spawned, _RawKind, Raw) ->
    #{parent => portable_term(element(4, Raw)),
      entry => portable_term(element(5, Raw))};
trace_details(send, _RawKind, Raw) ->
    #{message => portable_term(element(4, Raw)),
      receiver => portable_term(element(5, Raw))};
trace_details(send_to_non_existing_process, _RawKind, Raw) ->
    #{message => portable_term(element(4, Raw)),
      receiver => portable_term(element(5, Raw))};
trace_details('receive', _RawKind, Raw) ->
    #{message => portable_term(element(4, Raw))};
trace_details(exit, _RawKind, Raw) ->
    #{reason => portable_term(element(4, Raw))};
trace_details(Kind, _RawKind, Raw)
  when Kind =:= register; Kind =:= unregister ->
    #{registered_name => portable_term(element(4, Raw))};
trace_details(Kind, _RawKind, Raw)
  when Kind =:= link; Kind =:= unlink;
       Kind =:= getting_linked; Kind =:= getting_unlinked ->
    #{peer => portable_term(element(4, Raw))};
trace_details(Kind, _RawKind, Raw)
  when Kind =:= gc_start; Kind =:= gc_end;
       Kind =:= gc_minor_start; Kind =:= gc_minor_end;
       Kind =:= gc_major_start; Kind =:= gc_major_end;
       Kind =:= gc_max_heap_size ->
    #{info => portable_term(element(4, Raw))};
trace_details(Kind, _RawKind, Raw)
  when Kind =:= scheduler_in; Kind =:= scheduler_out;
       Kind =:= scheduler_in_exiting; Kind =:= scheduler_out_exiting;
       Kind =:= scheduler_out_exited ->
    #{mfa => portable_term(element(4, Raw))};
trace_details(unknown_runtime_event, RawKind, Raw) ->
    #{original_kind => portable_term(RawKind),
      detail => portable_term(Raw)};
trace_details(_Kind, _RawKind, Raw) ->
    #{detail => portable_term(Raw)}.

portable_term(Pid) when is_pid(Pid) ->
    #{term_type => pid, node => node(Pid),
      text => list_to_binary(pid_to_list(Pid))};
portable_term(Port) when is_port(Port) ->
    #{term_type => port, node => node(Port),
      text => list_to_binary(erlang:port_to_list(Port))};
portable_term(Reference) when is_reference(Reference) ->
    #{term_type => reference,
      text => list_to_binary(erlang:ref_to_list(Reference))};
portable_term(Function) when is_function(Function) ->
    #{term_type => function,
      text => unicode:characters_to_binary(io_lib:format("~tp", [Function]))};
portable_term(Tuple) when is_tuple(Tuple) ->
    list_to_tuple([portable_term(Value) || Value <- tuple_to_list(Tuple)]);
portable_term(List) when is_list(List) ->
    [portable_term(Value) || Value <- List];
portable_term(Map) when is_map(Map) ->
    maps:from_list([{portable_term(Key), portable_term(Value)}
                    || {Key, Value} <- maps:to_list(Map)]);
portable_term(Value) -> Value.
ERLANG
}

materialize_runtime_agent() {
  local directory=$1 source beam
  source="$directory/beam_flow_runtime_agent.erl"
  beam="$directory/beam_flow_runtime_agent.beam"
  runtime_agent_source >"$source"
  "$ERLC_COMMAND" +deterministic -Werror -o "$directory" "$source"
  [[ -f $beam && ! -L $beam ]] ||
    die "$EX_NOINPUT" "runtime agent compilation did not produce a regular BEAM"
  printf '%s\n' "$beam"
}

materialize_helper() { temporary_helper; }

temporary_helper() {
  local dir helper
  dir=$(mktemp -d "${TMPDIR:-/tmp}/beam-patch-helper.XXXXXX")
  helper="$dir/helper.escript"
  helper_source >"$helper"
  chmod 700 -- "$helper"
  printf '%s\n' "$helper"
}

run_helper() {
  BEAM_TOOLKIT_ERL_PATH=$ERL_COMMAND \
  BEAM_TOOLKIT_ERLC_PATH=$ERLC_COMMAND \
  BEAM_TOOLKIT_ESCRIPT_PATH=$ESCRIPT_COMMAND \
    "$ESCRIPT_COMMAND" "$@"
}

require_different() { [[ $1 != "$2" ]] || die "$EX_UNSAFE" "output aliases input: $1"; }

parse_options() {
  INPUT= WORKSPACE= ASSEMBLY= OUTPUT= ORIGINAL= CANDIDATE= ENTRY_LABEL= ALLOW_OTP= RUNTIME_BIN= KEY1_FILE= KEY2_FILE= FUNCTION= FROM_TERM= TO_TERM= EXPECTED_COUNT=
  MODE= SCOPE=supplied GRAPH= SCENARIO= NODE= COOKIE_FILE= FROM= FORMAT=term
  DURATION=30 MAX_EVENTS=100000 MAX_BYTES=1073741824 TRACE_BACKEND=auto ISOLATION=auto
  DIRECTION=both MAX_DEPTH=12
  AUTO_VERSION_OUTPUT=0 UNBOUNDED_LIVE_TRACE=0 ACKNOWLEDGE_LIVE_RISK=0 ALLOW_LEGACY_LIVE_TRACE=0
  BEAMS=()
  BEAM_DIRS=()
  PROCESS_SELECTORS=()
  FUNCTION_SELECTORS=()
  EVENT_SELECTORS=()
  while (($#)); do
    case $1 in
      --input|--workspace|--assembly|--output|--original|--candidate|--entry-label|--allow-otp-major|--runtime-bin|--key1-file|--key2-file|--function|--from-term|--to-term|--expected-count|--mode|--scope|--graph|--scenario|--node|--cookie-file|--duration|--max-events|--max-bytes|--trace-backend|--isolation|--direction|--max-depth|--from|--format|--beam|--beam-dir|--process|--functions|--events)
        (($# >= 2)) || die "$EX_USAGE" "missing value for $1"
        case $1 in
          --input) INPUT=$2 ;; --workspace) WORKSPACE=$2 ;; --assembly) ASSEMBLY=$2 ;;
          --output) OUTPUT=$2 ;; --original) ORIGINAL=$2 ;;
          --candidate) CANDIDATE=$2 ;; --entry-label) ENTRY_LABEL=$2 ;;
          --allow-otp-major) ALLOW_OTP=$2 ;;
          --runtime-bin) RUNTIME_BIN=$2 ;;
          --key1-file) KEY1_FILE=$2 ;;
          --key2-file) KEY2_FILE=$2 ;;
          --function) FUNCTION=$2 ;;
          --from-term) FROM_TERM=$2 ;;
          --to-term) TO_TERM=$2 ;;
          --expected-count) EXPECTED_COUNT=$2 ;;
          --mode) MODE=$2 ;;
          --scope) SCOPE=$2 ;;
          --graph) GRAPH=$2 ;;
          --scenario) SCENARIO=$2 ;;
          --node) NODE=$2 ;;
          --cookie-file) COOKIE_FILE=$2 ;;
          --duration) DURATION=$2 ;;
          --max-events) MAX_EVENTS=$2 ;;
          --max-bytes) MAX_BYTES=$2 ;;
          --trace-backend) TRACE_BACKEND=$2 ;;
          --isolation) ISOLATION=$2 ;;
          --direction) DIRECTION=$2 ;;
          --max-depth) MAX_DEPTH=$2 ;;
          --from) FROM=$2 ;;
          --format) FORMAT=$2 ;;
          --beam) BEAMS+=("$2") ;;
          --beam-dir) BEAM_DIRS+=("$2") ;;
          --process) PROCESS_SELECTORS+=("$2") ;;
          --functions) FUNCTION_SELECTORS+=("$2") ;;
          --events) EVENT_SELECTORS+=("$2") ;;
        esac
        shift 2
        ;;
      --auto-version-output)
        AUTO_VERSION_OUTPUT=1
        shift
        ;;
      --unbounded-live-trace)
        UNBOUNDED_LIVE_TRACE=1
        shift
        ;;
      --acknowledge-live-risk)
        ACKNOWLEDGE_LIVE_RISK=1
        shift
        ;;
      --allow-legacy-live-trace)
        ALLOW_LEGACY_LIVE_TRACE=1
        shift
        ;;
      *) die "$EX_USAGE" "unknown or incomplete option: $1" ;;
    esac
  done
}

require_positive_integer_option() {
  local name=$1 value=$2
  [[ $value =~ ^[1-9][0-9]*$ ]] || die "$EX_USAGE" "$name must be a positive integer"
}

require_nonnegative_integer_option() {
  local name=$1 value=$2
  [[ $value =~ ^[0-9]+$ ]] || die "$EX_USAGE" "$name must be a nonnegative integer"
}

validate_flow_common_options() {
  case $SCOPE in single|supplied|tree) ;; *) die "$EX_USAGE" "invalid flow scope: $SCOPE" ;; esac
  case $TRACE_BACKEND in auto|session|dbg|legacy) ;; *) die "$EX_USAGE" "invalid trace backend: $TRACE_BACKEND" ;; esac
  case $ISOLATION in auto|namespace|process) ;; *) die "$EX_USAGE" "invalid isolation mode: $ISOLATION" ;; esac
  case $DIRECTION in callers|callees|both) ;; *) die "$EX_USAGE" "invalid query direction: $DIRECTION" ;; esac
  case $FORMAT in term|json) ;; *) die "$EX_USAGE" "invalid output format: $FORMAT" ;; esac
  require_nonnegative_integer_option --max-depth "$MAX_DEPTH"
}

validate_flow_command() {
  [[ -n $MODE && -n $OUTPUT ]] || die "$EX_USAGE" "flow requires --mode MODE --output FLOW_OR_TRACE_DIR"
  validate_flow_common_options
  if (( UNBOUNDED_LIVE_TRACE == 1 && ACKNOWLEDGE_LIVE_RISK == 0 )); then
    die "$EX_USAGE" "--unbounded-live-trace requires --acknowledge-live-risk"
  fi
  if (( ACKNOWLEDGE_LIVE_RISK == 1 && UNBOUNDED_LIVE_TRACE == 0 )) &&
     [[ $TRACE_BACKEND != legacy ]]; then
    die "$EX_USAGE" "--acknowledge-live-risk alone does not enable a tracing mode"
  fi
  if [[ $TRACE_BACKEND == legacy ]] &&
     (( ALLOW_LEGACY_LIVE_TRACE == 0 || ACKNOWLEDGE_LIVE_RISK == 0 )); then
    die "$EX_USAGE" "legacy tracing requires --allow-legacy-live-trace --acknowledge-live-risk"
  fi
  if (( ALLOW_LEGACY_LIVE_TRACE == 1 )) && [[ $TRACE_BACKEND != legacy ]]; then
    die "$EX_USAGE" "--allow-legacy-live-trace requires --trace-backend legacy"
  fi
  case $MODE in
    static)
      (( ${#BEAMS[@]} + ${#BEAM_DIRS[@]} > 0 )) ||
        die "$EX_USAGE" "static flow requires at least one --beam or --beam-dir"
      if [[ $SCOPE == single ]]; then
        (( ${#BEAMS[@]} == 1 && ${#BEAM_DIRS[@]} == 0 )) ||
          die "$EX_USAGE" "single scope requires exactly one --beam and no --beam-dir"
      fi
      [[ -z $GRAPH && -z $SCENARIO && -z $NODE && -z $COOKIE_FILE ]] ||
        die "$EX_USAGE" "static flow does not accept runtime graph, scenario, node, or cookie options"
      (( UNBOUNDED_LIVE_TRACE == 0 && ALLOW_LEGACY_LIVE_TRACE == 0 )) ||
        die "$EX_USAGE" "static flow does not accept live-trace risk flags"
      ;;
    isolated-runtime)
      [[ -n $GRAPH && -n $SCENARIO ]] ||
        die "$EX_USAGE" "isolated-runtime flow requires --graph FLOW_DIR --scenario SCENARIO.term"
      [[ -z $NODE && -z $COOKIE_FILE ]] ||
        die "$EX_USAGE" "isolated-runtime flow does not accept --node or --cookie-file"
      (( UNBOUNDED_LIVE_TRACE == 0 && ALLOW_LEGACY_LIVE_TRACE == 0 )) ||
        die "$EX_USAGE" "isolated-runtime flow does not accept live-trace risk flags"
      ;;
    live-runtime)
      [[ -n $GRAPH && -n $NODE && -n $COOKIE_FILE ]] ||
        die "$EX_USAGE" "live-runtime flow requires --graph FLOW_DIR --node NODE --cookie-file FILE"
      if (( UNBOUNDED_LIVE_TRACE == 0 )); then
        require_positive_integer_option --duration "$DURATION"
        require_positive_integer_option --max-events "$MAX_EVENTS"
        require_positive_integer_option --max-bytes "$MAX_BYTES"
      fi
      ;;
    *) die "$EX_USAGE" "invalid flow mode: $MODE" ;;
  esac
}

cleanup_flow_command() {
  if [[ -n ${LIVE_HELPER_PID:-} ]] && kill -0 "$LIVE_HELPER_PID" 2>/dev/null; then
    request_live_trace_stop signal_term
    local attempt
    for attempt in $(seq 1 50); do
      kill -0 "$LIVE_HELPER_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$LIVE_HELPER_PID" 2>/dev/null; then
      kill -TERM "$LIVE_HELPER_PID" 2>/dev/null || true
    fi
    wait "$LIVE_HELPER_PID" 2>/dev/null || true
    LIVE_HELPER_PID=
  fi
  cleanup_directory_transaction
  if [[ -n ${FLOW_HELPER_DIR:-} && -d $FLOW_HELPER_DIR && ! -L $FLOW_HELPER_DIR ]]; then
    rm -rf -- "$FLOW_HELPER_DIR"
  fi
}

request_live_trace_stop() {
  local reason=$1
  [[ -n ${LIVE_CONTROL_FILE:-} ]] || return 0
  if [[ -z ${LIVE_STOP_REASON:-} ]]; then
    LIVE_STOP_REASON=$reason
    printf '%s\n' "$reason" >"$LIVE_CONTROL_FILE"
  fi
  LIVE_SIGNAL_INTERRUPTED=1
}

wait_for_live_helper() {
  local status=0
  while :; do
    status=0
    wait "$LIVE_HELPER_PID" || status=$?
    if (( ${LIVE_SIGNAL_INTERRUPTED:-0} == 1 && status >= 128 )); then
      LIVE_SIGNAL_INTERRUPTED=0
      continue
    fi
    return "$status"
  done
}

select_isolated_isolation() {
  case $ISOLATION in
    process)
      ISOLATION_EFFECTIVE=process
      ;;
    auto)
      ISOLATION_EFFECTIVE=process
      printf '%s: namespace isolation was not capability-selected; using process isolation (not a security sandbox)\n' \
        "$PROGRAM" >&2
      ;;
    namespace)
      die "$EX_NOINPUT" "namespace isolation capability is unavailable in this implementation stage; use --isolation process"
      ;;
  esac
}

main() {
  local command=${1-help} helper input workspace output assembly extras original candidate key1 key2 function from_term to_term workspace_parent workspace_name graph scenario path
  case $command in help|-h|--help) usage; exit 0 ;; esac
  shift || true
  parse_options "$@"
  case $command in
    doctor) [[ -n $INPUT ]] || die "$EX_USAGE" "doctor requires --input BEAM" ;;
    workspace-status) [[ -n $WORKSPACE ]] || die "$EX_USAGE" "workspace-status requires --workspace DIR" ;;
    unpack) [[ -n $INPUT && -n $OUTPUT ]] || die "$EX_USAGE" "unpack requires --input INPUT --output OUTPUT" ;;
    decrypt-aes) [[ -n $INPUT && -n $OUTPUT && -n $KEY1_FILE && -n $KEY2_FILE ]] || die "$EX_USAGE" "decrypt-aes requires --input INPUT --output OUTPUT --key1-file FILE --key2-file FILE" ;;
    extract|roundtrip) [[ -n $INPUT && -n $WORKSPACE ]] || die "$EX_USAGE" "$command requires --input BEAM --workspace DIR" ;;
    rebuild) [[ -n $WORKSPACE && -n $ASSEMBLY && -n $OUTPUT ]] || die "$EX_USAGE" "rebuild requires --workspace WORKSPACE --assembly EDITED.S --output CANDIDATE.beam" ;;
    verify) [[ -n $ORIGINAL && -n $CANDIDATE ]] || die "$EX_USAGE" "verify requires --original ORIGINAL.beam --candidate CANDIDATE.beam" ;;
    export-function)
      [[ -n $WORKSPACE && -n $ASSEMBLY && -n $ENTRY_LABEL && -n $OUTPUT ]] || die "$EX_USAGE" "export-function requires --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --output FUNCTION.term"
      [[ $ENTRY_LABEL =~ ^[1-9][0-9]*$ ]] || die "$EX_USAGE" "--entry-label must be a positive integer"
      ;;
    replace-function) [[ -n $WORKSPACE && -n $ASSEMBLY && -n $FUNCTION && -n $OUTPUT ]] || die "$EX_USAGE" "replace-function requires --workspace WORKSPACE --assembly ASSEMBLY.S --function FUNCTION.term --output EDITED.S" ;;
    rewrite-function-term)
      [[ -n $WORKSPACE && -n $ASSEMBLY && -n $ENTRY_LABEL && -n $FROM_TERM && -n $TO_TERM && -n $EXPECTED_COUNT && -n $OUTPUT ]] ||
        die "$EX_USAGE" "rewrite-function-term requires --workspace WORKSPACE --assembly ASSEMBLY.S --entry-label N --from-term FROM.term --to-term TO.term --expected-count N --output EDITED.S"
      [[ $ENTRY_LABEL =~ ^[1-9][0-9]*$ ]] || die "$EX_USAGE" "--entry-label must be a positive integer"
      [[ $EXPECTED_COUNT =~ ^[1-9][0-9]*$ ]] || die "$EX_USAGE" "--expected-count must be a positive integer"
      ;;
    validate-assembly) [[ -n $WORKSPACE && -n $ASSEMBLY ]] || die "$EX_USAGE" "validate-assembly requires --workspace WORKSPACE --assembly ASSEMBLY.S" ;;
    neutral-line-canary)
      [[ -n $WORKSPACE && -n $ENTRY_LABEL && -n $OUTPUT ]] || die "$EX_USAGE" "neutral-line-canary requires --workspace WORKSPACE --entry-label N --output EDITED.S"
      [[ $ENTRY_LABEL =~ ^[1-9][0-9]*$ ]] || die "$EX_USAGE" "--entry-label must be a positive integer"
      ;;
    flow) validate_flow_command ;;
    flow-query)
      [[ -n $GRAPH && -n $FROM ]] || die "$EX_USAGE" "flow-query requires --graph FLOW_DIR --from MODULE:FUNCTION/ARITY"
      validate_flow_common_options
      ;;
    trace-scenario-check)
      [[ -n $SCENARIO ]] || die "$EX_USAGE" "trace-scenario-check requires --scenario SCENARIO.term"
      ;;
    trace-raw-check)
      [[ -n $INPUT ]] || die "$EX_USAGE" "trace-raw-check requires --input events.raw.etf"
      require_positive_integer_option --max-bytes "$MAX_BYTES"
      ;;
    *) die "$EX_USAGE" "unknown command: $command" ;;
  esac
  if [[ $AUTO_VERSION_OUTPUT == 1 ]]; then
    case $command in
      unpack|decrypt-aes|rebuild|export-function|replace-function|rewrite-function-term|neutral-line-canary) ;;
      *) die "$EX_USAGE" "--auto-version-output is not valid for $command" ;;
    esac
  fi
  if [[ $command == workspace-status ]]; then
    workspace_status_command "$WORKSPACE" "$INPUT"
    exit 0
  fi
  configure_runtime
  check_otp "$ALLOW_OTP"
  case $command in
    unpack)
      input=$(canonical_existing_file "$INPUT")
      select_output_path "$OUTPUT" unpack
      output=$SELECTED_OUTPUT
      require_different "$input" "$output"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" unpack "$input" "$output"
      report_output "$output"
      ;;
    decrypt-aes)
      input=$(canonical_existing_file "$INPUT")
      select_output_path "$OUTPUT" decrypt
      output=$SELECTED_OUTPUT
      key1=$(canonical_secret_file "$KEY1_FILE")
      key2=$(canonical_secret_file "$KEY2_FILE")
      require_different "$input" "$output"
      require_different "$output" "$key1"
      require_different "$output" "$key2"
      [[ $key1 != "$key2" ]] || die "$EX_UNSAFE" "key1 and key2 files must be distinct"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" decrypt_aes "$input" "$output" "$key1" "$key2"
      report_output "$output"
      ;;
    doctor)
      input=$(canonical_existing_file "$INPUT")
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" doctor "$input"
      ;;
    extract)
      input=$(canonical_existing_file "$INPUT")
      prepare_extract_workspace "$WORKSPACE" "$input"
      workspace=$PREPARED_WORKSPACE
      if [[ $PREPARED_WORKSPACE_REUSE == 1 ]]; then
        printf '%s: workspace already complete and input matches byte-for-byte: %s\n' "$PROGRAM" "$workspace" >&2
      else
        workspace_parent=${workspace%/*}
        workspace_name=${workspace##*/}
        staging_workspace=$(mktemp -d "$workspace_parent/.${workspace_name}.beam-patch-staging.XXXXXX")
        : >"$staging_workspace/.beam-patch-workspace"
        helper=$(materialize_helper "$staging_workspace")
        cleanup_dir=${helper%/*}
        trap 'rm -rf -- "$cleanup_dir" "$staging_workspace"' EXIT
        run_helper "$helper" extract "$input" "$staging_workspace"
        (cd -- "$staging_workspace" && sha256sum original.beam >original.sha256)
        mv -Tn -- "$staging_workspace" "$workspace"
        [[ ! -e $staging_workspace && ! -L $staging_workspace ]] ||
          die "$EX_EXISTS" "workspace appeared during transactional commit: $workspace"
        printf '%s: workspace committed transactionally: %s\n' "$PROGRAM" "$workspace" >&2
      fi
      ;;
    roundtrip)
      input=$(canonical_existing_file "$INPUT")
      workspace=$(require_extracted_workspace "$WORKSPACE")
      require_workspace_input_match "$input" "$workspace"
      output=$(canonical_new_path "$workspace/roundtrip.beam")
      if [[ -e $output || -L $output ]]; then
        die "$EX_EXISTS" "refusing existing roundtrip output: $output; run workspace-status and use a new --workspace path for a fresh roundtrip"
      fi
      helper=$(materialize_helper "$workspace")
      cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" roundtrip "$workspace/editable.S" "$workspace/extra_chunks.term" "$output" "$input"
      ;;
    rebuild)
      workspace=$(require_proven_workspace "$WORKSPACE")
      assembly=$(canonical_existing_file "$ASSEMBLY")
      select_output_path "$OUTPUT" candidate
      output=$SELECTED_OUTPUT
      require_different "$output" "$assembly"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" validate_edited_assembly "$workspace/editable.S" "$assembly"
      run_helper "$helper" rebuild "$assembly" "$workspace/extra_chunks.term" "$output"
      report_output "$output"
      ;;
    verify)
      original=$(canonical_existing_file "$ORIGINAL")
      candidate=$(canonical_existing_file "$CANDIDATE")
      require_different "$original" "$candidate"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" verify "$original" "$candidate"
      ;;
    export-function)
      workspace=$(require_proven_workspace "$WORKSPACE")
      assembly=$(canonical_existing_file "$ASSEMBLY")
      select_output_path "$OUTPUT" function
      output=$SELECTED_OUTPUT
      require_different "$output" "$assembly"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" validate_edited_assembly "$workspace/editable.S" "$assembly"
      run_helper "$helper" export_function "$assembly" "$ENTRY_LABEL" "$output"
      report_output "$output"
      ;;
    replace-function)
      workspace=$(require_proven_workspace "$WORKSPACE")
      assembly=$(canonical_existing_file "$ASSEMBLY")
      function=$(canonical_existing_file "$FUNCTION")
      select_output_path "$OUTPUT" edited-assembly
      output=$SELECTED_OUTPUT
      require_different "$output" "$assembly"
      require_different "$output" "$function"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" validate_edited_assembly "$workspace/editable.S" "$assembly"
      run_helper "$helper" replace_function "$assembly" "$function" "$workspace/extra_chunks.term" "$output"
      report_output "$output"
      ;;
    rewrite-function-term)
      workspace=$(require_proven_workspace "$WORKSPACE")
      assembly=$(canonical_existing_file "$ASSEMBLY")
      from_term=$(canonical_existing_file "$FROM_TERM")
      to_term=$(canonical_existing_file "$TO_TERM")
      select_output_path "$OUTPUT" edited-assembly
      output=$SELECTED_OUTPUT
      require_different "$output" "$assembly"
      require_different "$output" "$from_term"
      require_different "$output" "$to_term"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" validate_edited_assembly "$workspace/editable.S" "$assembly"
      run_helper "$helper" rewrite_function_term "$assembly" "$ENTRY_LABEL" "$from_term" "$to_term" "$EXPECTED_COUNT" "$workspace/extra_chunks.term" "$output"
      report_output "$output"
      ;;
    validate-assembly)
      workspace=$(require_proven_workspace "$WORKSPACE")
      assembly=$(canonical_existing_file "$ASSEMBLY")
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" validate_edited_assembly "$workspace/editable.S" "$assembly"
      run_helper "$helper" validate_assembly "$assembly" "$workspace/extra_chunks.term"
      ;;
    neutral-line-canary)
      workspace=$(require_proven_workspace "$WORKSPACE")
      select_output_path "$OUTPUT" canary
      output=$SELECTED_OUTPUT
      require_different "$output" "$workspace/editable.S"
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" validate_roundtrip_proof "$workspace"
      run_helper "$helper" neutral_line_canary "$workspace/editable.S" "$ENTRY_LABEL" "$output"
      report_output "$output"
      ;;
    flow)
      case $MODE in
        static)
          local -a canonical_beams=() canonical_beam_dirs=()
          for path in "${BEAMS[@]}"; do canonical_beams+=("$(canonical_existing_file "$path")"); done
          for path in "${BEAM_DIRS[@]}"; do canonical_beam_dirs+=("$(canonical_existing_directory "$path")"); done
          begin_directory_transaction "$OUTPUT"
          helper=$(temporary_helper)
          FLOW_HELPER_DIR=${helper%/*}
          trap cleanup_flow_command EXIT INT TERM
          run_helper "$helper" flow_static "$TRANSACTION_DIR" "$SCOPE" \
            "${#canonical_beams[@]}" "${#canonical_beam_dirs[@]}" \
            "${canonical_beams[@]}" "${canonical_beam_dirs[@]}"
          if command -v dot >/dev/null 2>&1; then
            dot -Tsvg "$TRANSACTION_DIR/callgraph.dot" \
              -o "$TRANSACTION_DIR/callgraph.svg"
            for path in "$TRANSACTION_DIR"/cfg/*.dot; do
              [[ -f $path ]] || continue
              dot -Tsvg "$path" -o "${path%.dot}.svg"
            done
          fi
          commit_directory_transaction .beam-flow-ir
          report_output "$TRANSACTION_TARGET"
          ;;
        isolated-runtime)
          graph=$(canonical_existing_directory "$GRAPH")
          canonical_existing_file "$graph/.beam-flow-ir" >/dev/null
          scenario=$(canonical_existing_file "$SCENARIO")
          select_isolated_isolation
          begin_directory_transaction "$OUTPUT"
          helper=$(temporary_helper)
          FLOW_HELPER_DIR=${helper%/*}
          trap cleanup_flow_command EXIT INT TERM
          runtime_agent=$(materialize_runtime_agent "$FLOW_HELPER_DIR")
          run_helper "$helper" flow_isolated "$TRANSACTION_DIR" "$graph" \
            "$scenario" "$ISOLATION" "$ISOLATION_EFFECTIVE" "$runtime_agent"
          if command -v dot >/dev/null 2>&1; then
            dot -Tsvg "$TRANSACTION_DIR/runtime.dot" \
              -o "$TRANSACTION_DIR/runtime.svg"
          fi
          trace_state=$(<"$TRANSACTION_DIR/trace-status")
          case $trace_state in
            complete|partial) ;;
            *) die "$EX_NOINPUT" "isolated trace helper wrote an invalid state: $trace_state" ;;
          esac
          commit_directory_transaction .beam-flow-trace
          report_output "$TRANSACTION_TARGET"
          if [[ $trace_state == partial ]]; then
            die "$EX_SOFTWARE" "isolated trace ended partially; cleanup and captured evidence are recorded in $TRANSACTION_TARGET/trace-manifest.term"
          fi
          ;;
        live-runtime)
          graph=$(canonical_existing_directory "$GRAPH")
          canonical_existing_file "$graph/.beam-flow-ir" >/dev/null
          cookie=$(canonical_secret_file "$COOKIE_FILE")
          begin_directory_transaction "$OUTPUT"
          helper=$(temporary_helper)
          FLOW_HELPER_DIR=${helper%/*}
          LIVE_CONTROL_FILE="$FLOW_HELPER_DIR/live-control"
          LIVE_HELPER_PID=
          LIVE_STOP_REASON=
          LIVE_SIGNAL_INTERRUPTED=0
          trap cleanup_flow_command EXIT
          trap 'request_live_trace_stop signal_int' INT
          trap 'request_live_trace_stop signal_term' TERM
          runtime_agent=$(materialize_runtime_agent "$FLOW_HELPER_DIR")
          live_duration=$DURATION
          live_max_events=$MAX_EVENTS
          live_max_bytes=$MAX_BYTES
          if (( UNBOUNDED_LIVE_TRACE == 1 )); then
            live_duration=infinity
            live_max_events=infinity
            live_max_bytes=infinity
          fi
          legacy_authorized=false
          if [[ $TRACE_BACKEND == legacy ]] &&
             (( ALLOW_LEGACY_LIVE_TRACE == 1 && ACKNOWLEDGE_LIVE_RISK == 1 )); then
            legacy_authorized=true
          fi
          run_helper "$helper" flow_live "$TRANSACTION_DIR" "$graph" \
            "$NODE" "$cookie" "$TRACE_BACKEND" "$live_duration" \
            "$live_max_events" "$live_max_bytes" "$runtime_agent" \
            "$LIVE_CONTROL_FILE" "$legacy_authorized" \
            "${#PROCESS_SELECTORS[@]}" "${#FUNCTION_SELECTORS[@]}" \
            "${#EVENT_SELECTORS[@]}" "${PROCESS_SELECTORS[@]}" \
            "${FUNCTION_SELECTORS[@]}" "${EVENT_SELECTORS[@]}" &
          LIVE_HELPER_PID=$!
          live_helper_status=0
          wait_for_live_helper || live_helper_status=$?
          LIVE_HELPER_PID=
          (( live_helper_status == 0 )) || exit "$live_helper_status"
          if command -v dot >/dev/null 2>&1; then
            dot -Tsvg "$TRANSACTION_DIR/runtime.dot" \
              -o "$TRANSACTION_DIR/runtime.svg"
          fi
          trace_state=$(<"$TRANSACTION_DIR/trace-status")
          case $trace_state in
            complete|partial) ;;
            *) die "$EX_NOINPUT" "live trace helper wrote an invalid state: $trace_state" ;;
          esac
          commit_directory_transaction .beam-flow-trace
          report_output "$TRANSACTION_TARGET"
          if [[ $trace_state == partial ]]; then
            die "$EX_SOFTWARE" "live trace ended partially; cleanup and captured evidence are recorded in $TRANSACTION_TARGET/trace-manifest.term"
          fi
          ;;
      esac
      ;;
    flow-query)
      graph=$(canonical_existing_directory "$GRAPH")
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" flow_query "$graph" "$FROM" "$DIRECTION" "$MAX_DEPTH" "$FORMAT"
      ;;
    trace-scenario-check)
      scenario=$(canonical_existing_file "$SCENARIO")
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" scenario_check "$scenario"
      ;;
    trace-raw-check)
      input=$(canonical_existing_file "$INPUT")
      helper=$(temporary_helper); cleanup_dir=${helper%/*}; trap 'rm -rf -- "$cleanup_dir"' EXIT
      run_helper "$helper" trace_raw_check "$input" "$MAX_BYTES"
      ;;
    *) die "$EX_USAGE" "unknown command: $command" ;;
  esac
}

main "$@"
