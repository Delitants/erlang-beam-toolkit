#!/usr/bin/env escript
%%! -noshell
-mode(compile).

main(["manifest", Path, ExpectedState]) ->
    {ok, [Manifest]} = file:consult(Path),
    beam_flow_ir_v1 = maps:get(schema, Manifest),
    Expected = list_to_atom(ExpectedState),
    Expected = maps:get(state, Manifest),
    Counts = maps:get(counts, Manifest),
    true = is_map(Counts),
    halt(0);
main(["cfg", GraphDir]) ->
    assert_cfg(GraphDir),
    halt(0);
main(["dataflow", GraphDir]) ->
    assert_dataflow(GraphDir),
    halt(0);
main(["linked", GraphDir]) ->
    assert_linked(GraphDir),
    halt(0);
main(["module_count", GraphDir, ExpectedText]) ->
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    Expected = list_to_integer(ExpectedText),
    Expected = length(maps:get(modules, IR)),
    halt(0);
main(["query", QueryPath, ExpectedDirection, ExpectedDepthText]) ->
    assert_query(QueryPath, ExpectedDirection, ExpectedDepthText),
    halt(0);
main(["formats", GraphDir]) ->
    assert_formats(GraphDir),
    halt(0);
main(["query_json", QueryPath]) ->
    assert_query_json(QueryPath),
    halt(0);
main(["html", GraphDir]) ->
    assert_html(GraphDir),
    halt(0);
main(["isolated", TraceDir]) ->
    assert_isolated(TraceDir),
    halt(0);
main(["isolated_partial", TraceDir]) ->
    assert_isolated_partial(TraceDir),
    halt(0);
main(["runtime_stream", TraceDir]) ->
    assert_runtime_stream(TraceDir),
    halt(0);
main(["overlay", TraceDir, GraphDir]) ->
    assert_runtime_overlay(TraceDir, GraphDir),
    halt(0);
main(["live", TraceDir, ExpectedReason, ExpectedNode]) ->
    assert_live(TraceDir, ExpectedReason, ExpectedNode),
    halt(0);
main(["live_backend", TraceDir, ExpectedReason, ExpectedNode,
      ExpectedBackend]) ->
    assert_live_backend(TraceDir, ExpectedReason, ExpectedNode,
                        ExpectedBackend),
    halt(0);
main(["live_signal", TraceDir, ExpectedNode]) ->
    assert_live_signal(TraceDir, ExpectedNode),
    halt(0);
main(_) ->
    halt(64).

assert_cfg(GraphDir) ->
    Functions = consult_list(filename:join(GraphDir, "functions.term")),
    Blocks = consult_list(filename:join(GraphDir, "blocks.term")),
    Instructions = consult_list(filename:join(GraphDir, "instructions.term")),
    Edges = consult_list(filename:join(GraphDir, "cfg-edges.term")),
    Unsupported = consult_list(filename:join(GraphDir, "unsupported.term")),
    true = length(Functions) >= 5,
    true = length(Blocks) > length(Functions),
    true = length(Instructions) > length(Blocks),
    true = is_list(Unsupported),
    FunctionIds = [maps:get(id, F) || F <- Functions],
    BlockIds = [maps:get(id, B) || B <- Blocks],
    InstructionIds = [maps:get(id, I) || I <- Instructions],
    true = unique(FunctionIds),
    true = unique(BlockIds),
    true = unique(InstructionIds),
    true = lists:all(fun(B) -> lists:member(maps:get(function_id, B), FunctionIds) end, Blocks),
    true = lists:all(fun(I) -> lists:member(maps:get(block_id, I), BlockIds) end, Instructions),
    true = lists:all(fun(F) -> lists:member(maps:get(entry_block_id, F), BlockIds) end, Functions),
    true = lists:all(
      fun(E) ->
          lists:member(maps:get(source_block_id, E), BlockIds) andalso
          lists:member(maps:get(target_block_id, E), BlockIds)
      end, Edges),
    Kinds = lists:usort([maps:get(kind, E) || E <- Edges]),
    true = lists:member(test_pass, Kinds),
    true = lists:member(test_fail, Kinds),
    true = lists:member(receive_wait, Kinds),
    true = lists:member(exception, Kinds),
    FuncInfoBlocks = lists:usort(
      [maps:get(block_id, I) || I <- Instructions,
       is_func_info(maps:get(raw_instruction, I))]),
    true = lists:all(
      fun(BlockId) ->
          not lists:any(fun(E) -> maps:get(source_block_id, E) =:= BlockId end,
                        Edges)
      end, FuncInfoBlocks),
    Sum = lists:sum([maps:get(instruction_count, F) || F <- Functions]),
    Sum = length(Instructions),
    ok.

consult_list(Path) ->
    {ok, [Value]} = file:consult(Path),
    true = is_list(Value),
    Value.

consult_one(Path) ->
    {ok, [Value]} = file:consult(Path),
    Value.

unique(Values) -> length(Values) =:= length(lists:usort(Values)).

is_func_info(Instruction) when is_tuple(Instruction), tuple_size(Instruction) > 0 ->
    element(1, Instruction) =:= func_info;
is_func_info(_) -> false.

assert_dataflow(GraphDir) ->
    Blocks = consult_list(filename:join(GraphDir, "blocks.term")),
    States = consult_list(filename:join(GraphDir, "block-states.term")),
    Calls = consult_list(filename:join(GraphDir, "dynamic-calls.term")),
    BlockIds = lists:sort([maps:get(id, B) || B <- Blocks]),
    BlockIds = lists:sort([maps:get(block_id, S) || S <- States]),
    true = lists:all(fun(S) ->
        maps:is_key(state_in, S) andalso maps:is_key(state_out, S)
    end, States),
    Certainties = lists:usort(
      [maps:get(certainty, maps:get(resolution, C)) || C <- Calls]),
    [exact, partial, possible, unresolved] = lists:sort(Certainties),
    true = lists:any(
      fun(#{resolution := #{certainty := exact,
                            target := {erlang, length, 1}}}) -> true;
         (_) -> false
      end, Calls),
    true = lists:any(
      fun(#{resolution := #{certainty := possible, targets := Targets}}) ->
              lists:sort(Targets) =:= lists:sort([{erlang, abs, 1},
                                                  {erlang, round, 1}]);
         (_) -> false
      end, Calls),
    ok.

assert_linked(GraphDir) ->
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    beam_flow_ir_v1 = maps:get(schema, IR),
    complete = maps:get(state, IR),
    Modules = maps:get(modules, IR),
    2 = length(Modules),
    Edges = maps:get(call_edges, IR),
    true = lists:any(
      fun(#{caller_mfa := {flow_cross_a, start, 1},
            target_mfa := {flow_cross_b, step, 1},
            target_kind := internal}) -> true;
         (_) -> false
      end, Edges),
    Components = maps:get(strongly_connected_components, IR),
    true = lists:any(
      fun(Component) ->
          Members = lists:sort([function_mfa(Id) || Id <- Component]),
          lists:member({flow_cross_b, even, 1}, Members) andalso
          lists:member({flow_cross_b, odd, 1}, Members)
      end, Components),
    true = lists:any(
      fun(#{target_kind := external, target_mfa := {erlang, _, _}}) -> true;
         (_) -> false
      end, Edges),
    Counts = maps:get(counts, IR),
    true = length(maps:get(functions, IR)) =:= maps:get(functions, Counts),
    true = length(maps:get(instructions, IR)) =:= maps:get(instructions, Counts),
    ok.

function_mfa({function, Module, Name, Arity, _Entry}) ->
    {Module, Name, Arity};
function_mfa(_) -> unknown.

assert_query(QueryPath, ExpectedDirection, ExpectedDepthText) ->
    Query = consult_one(QueryPath),
    beam_flow_query_v1 = maps:get(schema, Query),
    Direction = list_to_atom(ExpectedDirection),
    Direction = maps:get(direction, Query),
    Depth = list_to_integer(ExpectedDepthText),
    Depth = maps:get(max_depth, Query),
    true = maps:get(functions, maps:get(view_counts, Query)) >= 1,
    true = maps:get(functions, maps:get(authoritative_graph_counts, Query)) >=
           maps:get(functions, maps:get(view_counts, Query)),
    ok.

assert_formats(GraphDir) ->
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    Counts = maps:get(counts, IR),
    {ok, JsonBinary} = file:read_file(filename:join(GraphDir, "flow-ir.json")),
    Json = json:decode(JsonBinary),
    JsonCounts = maps:get(<<"counts">>, Json),
    true = maps:get(functions, Counts) =:= maps:get(<<"functions">>, JsonCounts),
    true = maps:get(instructions, Counts) =:= maps:get(<<"instructions">>, JsonCounts),
    {ok, Dot} = file:read_file(filename:join(GraphDir, "callgraph.dot")),
    true = binary:match(Dot, <<"digraph beam_flow">>) =/= nomatch,
    true = length(binary:matches(Dot, <<"shape=box">>)) >=
           maps:get(functions, Counts),
    {ok, GraphML} = file:read_file(filename:join(GraphDir, "callgraph.graphml")),
    true = binary:match(GraphML, <<"<graphml">>) =/= nomatch,
    true = length(binary:matches(GraphML, <<"<node id=">>)) >=
           maps:get(functions, Counts),
    CfgIndex = consult_one(filename:join(GraphDir, "cfg-index.term")),
    true = maps:get(functions, Counts) =:= length(CfgIndex),
    true = lists:all(fun(#{dot := DotName}) ->
        filelib:is_regular(filename:join([GraphDir, "cfg", DotName]))
    end, CfgIndex),
    case file:read_file(filename:join(GraphDir, "callgraph.svg")) of
        {ok, Svg} -> true = binary:match(Svg, <<"<svg">>) =/= nomatch;
        {error, enoent} -> ok
    end,
    ok.

assert_query_json(QueryPath) ->
    {ok, Binary} = file:read_file(QueryPath),
    Query = json:decode(Binary),
    <<"beam_flow_query_v1">> = maps:get(<<"schema">>, Query),
    true = maps:get(<<"functions">>, maps:get(<<"view_counts">>, Query)) >= 1,
    ok.

assert_html(GraphDir) ->
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    {ok, Html} = file:read_file(filename:join(GraphDir, "flow.html")),
    {match, [Embedded]} = re:run(
      Html,
      <<"<script id=\"beam-flow-data\" type=\"application/json\">(.*?)</script>">>,
      [dotall, {capture, [1], binary}]),
    Data = json:decode(Embedded),
    Functions = maps:get(<<"functions">>, Data),
    true = length(Functions) =:= length(maps:get(functions, IR)),
    JsonIds = [maps:get(<<"etf_base64">>, maps:get(<<"id">>, Function))
               || Function <- Functions],
    true = unique(JsonIds),
    true = maps:get(<<"instructions">>, maps:get(<<"counts">>, Data)) =:=
           maps:get(instructions, maps:get(counts, IR)),
    nomatch = re:run(Html, <<"<(script|link)[^>]+(https?:)?//">>, [caseless]),
    true = binary:match(Html, <<"Complete function inventory">>) =/= nomatch,
    true = binary:match(Html, <<"Runtime unavailable">>) =/= nomatch,
    ok.

assert_isolated(TraceDir) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    beam_flow_trace_v1 = maps:get(schema, Manifest),
    complete = maps:get(state, Manifest),
    isolated_runtime = maps:get(mode, Manifest),
    Node = maps:get(node, Manifest),
    true = is_atom(Node),
    true = Node =/= nonode@nohost,
    Scenario = maps:get(scenario, Manifest),
    passed = maps:get(status, Scenario),
    true = maps:get(assertions_passed, Scenario) >= 1,
    OnLoad = maps:get(on_load, Manifest),
    true = lists:member(flow_on_load_fixture, maps:get(invoked, OnLoad)),
    Cleanup = maps:get(cleanup, Manifest),
    true = maps:get(trace_session_destroyed, Cleanup),
    true = maps:get(peer_stopped, Cleanup),
    false = maps:get(controller_alive_after_stop, Cleanup),
    Isolation = maps:get(isolation, Manifest),
    process = maps:get(requested, Isolation),
    process = maps:get(effective, Isolation),
    Events = consult_list(filename:join(TraceDir, "events.term")),
    true = length(Events) =:= maps:get(events, maps:get(counts, Manifest)),
    Kinds = lists:usort([maps:get(kind, Event) || Event <- Events]),
    true = lists:all(fun(Kind) -> lists:member(Kind, Kinds) end,
                     [call, return_from, spawn, exit, send, 'receive']),
    true = lists:any(fun(#{kind := on_load,
                           mfa := {flow_on_load_fixture, init, 0}}) -> true;
                        (_) -> false
                     end, Events),
    true = lists:any(fun(#{kind := call,
                           mfa := {flow_runtime_fixture, call_chain, 1}}) -> true;
                        (_) -> false
                     end, Events),
    ok.

assert_isolated_partial(TraceDir) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    beam_flow_trace_v1 = maps:get(schema, Manifest),
    partial = maps:get(state, Manifest),
    isolated_runtime = maps:get(mode, Manifest),
    Scenario = maps:get(scenario, Manifest),
    Status = maps:get(status, Scenario),
    true = lists:member(Status, [failed, timeout]),
    Cleanup = maps:get(cleanup, Manifest),
    true = maps:get(trace_session_destroyed, Cleanup),
    true = maps:get(delivery_confirmed, Cleanup),
    true = maps:get(peer_stopped, Cleanup),
    false = maps:get(controller_alive_after_stop, Cleanup),
    Events = consult_list(filename:join(TraceDir, "events.term")),
    true = length(Events) =:= maps:get(events, maps:get(counts, Manifest)),
    ok.

assert_runtime_stream(TraceDir) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    Completeness = consult_one(
      filename:join(TraceDir, "trace-completeness.term")),
    beam_flow_trace_completeness_v1 = maps:get(schema, Completeness),
    RawCount = count_raw_frames(
      filename:join(TraceDir, "events.raw.etf")),
    {ok, JsonlBinary} = file:read_file(
      filename:join(TraceDir, "events.normalized.jsonl")),
    JsonLines = [Line || Line <- binary:split(JsonlBinary, <<"\n">>, [global]),
                         Line =/= <<>>],
    JsonEvents = [json:decode(Line) || Line <- JsonLines],
    Counts = maps:get(counts, Manifest),
    EventCount = maps:get(events, Counts),
    EventCount = RawCount,
    EventCount = length(JsonEvents),
    EventCount = maps:get(raw_frames, Counts),
    EventCount = maps:get(normalized_records, Counts),
    EventCount = maps:get(raw_frames, Completeness),
    EventCount = maps:get(normalized_records, Completeness),
    confirmed = maps:get(drain, Completeness),
    confirmed = maps:get(cleanup, Completeness),
    none = maps:get(loss, Completeness),
    ExpectedSequences = lists:seq(1, EventCount),
    ExpectedSequences =
        [maps:get(<<"sequence">>, Event) || Event <- JsonEvents],
    true = lists:all(fun(Event) ->
        maps:is_key(<<"correlation">>, Event) andalso
        maps:is_key(<<"call_depth">>, Event)
    end, JsonEvents),
    ok.

assert_runtime_overlay(TraceDir, GraphDir) ->
    IR = consult_one(filename:join(GraphDir, "flow-ir.term")),
    Overlay = consult_one(filename:join(TraceDir, "runtime-overlay.term")),
    beam_flow_runtime_overlay_v1 = maps:get(schema, Overlay),
    complete = maps:get(state, Overlay),
    StaticCounts = maps:get(counts, IR),
    StaticCounts = maps:get(static_counts, Overlay),
    ExpectedStaticDigest = crypto:hash(
      sha256, term_to_binary(maps:get(call_edges, IR), [deterministic])),
    ExpectedStaticDigest = maps:get(static_call_edges_sha256, Overlay),
    Functions = maps:get(functions, Overlay),
    true = lists:any(
      fun(#{mfa := {flow_runtime_fixture, call_chain, 1},
            observed_calls := Count}) -> Count >= 1;
         (_) -> false
      end, Functions),
    true = lists:any(
      fun(#{mfa := {flow_runtime_fixture, fail, 0},
            observed_exceptions := Count}) -> Count >= 1;
         (_) -> false
      end, Functions),
    Unmatched = consult_list(filename:join(TraceDir,
                                           "runtime-unmatched.term")),
    true = lists:any(
      fun(#{mfa := {lists, reverse, 1},
            reason := unsupplied_module}) -> true;
         (_) -> false
      end, Unmatched),
    Processes = consult_list(filename:join(TraceDir,
                                           "runtime-processes.term")),
    true = length(Processes) >= 2,
    true = lists:any(fun(Process) ->
        maps:get(parent_id, Process, undefined) =/= undefined
    end, Processes),
    RuntimeEdges = consult_one(filename:join(TraceDir,
                                             "runtime-edges.term")),
    true = lists:any(fun(Edge) ->
        maps:get(status, Edge, unmatched) =:= matched
    end, maps:get(message_edges, RuntimeEdges)),
    true = length(maps:get(spawn_edges, RuntimeEdges)) >= 1,
    {ok, TimelineBinary} = file:read_file(
      filename:join(TraceDir, "timeline.json")),
    Timeline = json:decode(TimelineBinary),
    EventCount = maps:get(events, maps:get(counts,
                                           consult_one(filename:join(
                                             TraceDir,
                                             "trace-manifest.term")))),
    EventCount = length(Timeline),
    ExpectedSequences = lists:seq(1, EventCount),
    ExpectedSequences = [maps:get(<<"sequence">>, Event)
                         || Event <- Timeline],
    {ok, Dot} = file:read_file(filename:join(TraceDir, "runtime.dot")),
    true = binary:match(Dot, <<"runtime-observed">>) =/= nomatch,
    {ok, Html} = file:read_file(filename:join(TraceDir, "flow.html")),
    true = binary:match(Html, <<"Runtime execution overlay">>) =/= nomatch,
    nomatch = re:run(Html, <<"<(script|link)[^>]+(https?:)?//">>, [caseless]),
    ok.

count_raw_frames(Path) ->
    {ok, Device} = file:open(Path, [read, raw, binary]),
    try count_raw_frames(Device, 0)
    after ok = file:close(Device)
    end.

count_raw_frames(Device, Count) ->
    case file:read(Device, 8) of
        eof -> Count;
        {ok, <<Length:64/unsigned-big>>} ->
            {ok, Payload} = file:read(Device, Length),
            Length = byte_size(Payload),
            _ = binary_to_term(Payload),
            count_raw_frames(Device, Count + 1)
    end.

assert_live(TraceDir, ExpectedReasonText, ExpectedNodeText) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    beam_flow_trace_v1 = maps:get(schema, Manifest),
    complete = maps:get(state, Manifest),
    live_runtime = maps:get(mode, Manifest),
    ExpectedReason = list_to_atom(ExpectedReasonText),
    ExpectedReason = maps:get(stop_reason, maps:get(capture, Manifest)),
    ExpectedNode = list_to_atom(ExpectedNodeText),
    ExpectedNode = maps:get(node, Manifest),
    session = maps:get(trace_backend, Manifest),
    CodeIdentity = maps:get(code_identity, Manifest),
    true = maps:get(unchanged, CodeIdentity),
    Before = maps:get(before, CodeIdentity),
    Before = maps:get('after', CodeIdentity),
    Cleanup = maps:get(cleanup, Manifest),
    true = maps:get(trace_session_destroyed, Cleanup),
    false = maps:get(owned_session_present_after_destroy, Cleanup),
    true = maps:get(temporary_agent_unloaded, Cleanup),
    true = maps:get(target_responsive_after, Cleanup),
    true = maps:get(events, maps:get(counts, Manifest)) > 0,
    assert_runtime_stream(TraceDir),
    ok.

assert_live_backend(TraceDir, ExpectedReasonText, ExpectedNodeText,
                    ExpectedBackendText) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    beam_flow_trace_v1 = maps:get(schema, Manifest),
    complete = maps:get(state, Manifest),
    live_runtime = maps:get(mode, Manifest),
    ExpectedReason = list_to_atom(ExpectedReasonText),
    ExpectedReason = maps:get(stop_reason, maps:get(capture, Manifest)),
    ExpectedNode = list_to_atom(ExpectedNodeText),
    ExpectedNode = maps:get(node, Manifest),
    ExpectedBackend = list_to_atom(ExpectedBackendText),
    ExpectedBackend = maps:get(trace_backend, Manifest),
    assert_live_identity_and_cleanup(Manifest, ExpectedBackend),
    assert_runtime_stream(TraceDir),
    ok.

assert_live_signal(TraceDir, ExpectedNodeText) ->
    Manifest = consult_one(filename:join(TraceDir, "trace-manifest.term")),
    beam_flow_trace_v1 = maps:get(schema, Manifest),
    partial = maps:get(state, Manifest),
    live_runtime = maps:get(mode, Manifest),
    signal_int = maps:get(stop_reason, maps:get(capture, Manifest)),
    ExpectedNode = list_to_atom(ExpectedNodeText),
    ExpectedNode = maps:get(node, Manifest),
    session = maps:get(trace_backend, Manifest),
    Bounds = maps:get(bounds, Manifest),
    infinity = maps:get(duration_ms, Bounds),
    infinity = maps:get(max_events, Bounds),
    infinity = maps:get(max_bytes, Bounds),
    assert_live_identity_and_cleanup(Manifest, session),
    assert_runtime_stream(TraceDir),
    ok.

assert_live_identity_and_cleanup(Manifest, Backend) ->
    CodeIdentity = maps:get(code_identity, Manifest),
    true = maps:get(unchanged, CodeIdentity),
    Before = maps:get(before, CodeIdentity),
    Before = maps:get('after', CodeIdentity),
    Cleanup = maps:get(cleanup, Manifest),
    true = maps:get(backend_cleanup_confirmed, Cleanup),
    true = maps:get(temporary_agent_unloaded, Cleanup),
    true = maps:get(target_responsive_after, Cleanup),
    true = maps:get(events, maps:get(counts, Manifest)) > 0,
    case Backend of
        dbg -> true = maps:get(dbg_session_destroyed, Cleanup);
        legacy ->
            true = maps:get(legacy_state_restored, Cleanup),
            SnapshotCounts = maps:get(legacy_snapshot_counts, Cleanup),
            true = maps:get(processes, SnapshotCounts) >= 1,
            true = maps:get(functions, SnapshotCounts) >= 1;
        session -> true = maps:get(trace_session_destroyed, Cleanup)
    end,
    ok.
