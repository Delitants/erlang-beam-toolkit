-module(flow_runtime_fixture).
-export([call_chain/1, fail/0, catch_fail/0, start_worker/1, worker/1,
         start_live/0, live_loop/0, start_legacy_state/0,
         assert_legacy_state/0, clear_legacy_state/0, legacy_sink/0]).

call_chain(Value) ->
    lists:reverse([Value]).

fail() ->
    erlang:error(expected_failure).

catch_fail() ->
    try fail() of
        _ -> unexpected_success
    catch
        error:expected_failure -> expected_failure
    end.

start_worker(Parent) ->
    spawn(?MODULE, worker, [Parent]).

worker(Parent) ->
    receive
        {echo, Value} ->
            Parent ! {echoed, Value},
            worker(Parent);
        stop ->
            ok
    end.

start_live() ->
    true = register(beam_flow_live_worker, spawn(?MODULE, live_loop, [])),
    ok.

live_loop() ->
    _ = call_chain(pulse),
    receive
        stop -> ok
    after 2 ->
        live_loop()
    end.

start_legacy_state() ->
    undefined = whereis(beam_flow_legacy_sink),
    Worker = whereis(beam_flow_live_worker),
    true = is_pid(Worker),
    Sink = spawn(?MODULE, legacy_sink, []),
    true = register(beam_flow_legacy_sink, Sink),
    1 = erlang:trace(Worker, true, [send, {tracer, Sink}]),
    1 = erlang:trace_pattern({?MODULE, call_chain, 1}, true, [local]),
    ok.

assert_legacy_state() ->
    Worker = whereis(beam_flow_live_worker),
    Sink = whereis(beam_flow_legacy_sink),
    {flags, [send]} = erlang:trace_info(Worker, flags),
    {tracer, Sink} = erlang:trace_info(Worker, tracer),
    {traced, local} = erlang:trace_info({?MODULE, call_chain, 1}, traced),
    {match_spec, MatchSpec} = erlang:trace_info(
      {?MODULE, call_chain, 1}, match_spec),
    true = MatchSpec =/= false,
    ok.

clear_legacy_state() ->
    Worker = whereis(beam_flow_live_worker),
    Sink = whereis(beam_flow_legacy_sink),
    1 = erlang:trace(Worker, false, [all]),
    1 = erlang:trace_pattern({?MODULE, call_chain, 1}, false, [local]),
    true = unregister(beam_flow_legacy_sink),
    Sink ! stop,
    ok.

legacy_sink() ->
    receive
        stop -> ok;
        _TraceEvent -> legacy_sink()
    end.
