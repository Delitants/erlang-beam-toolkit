-module(flow_branch_fixture).
-export([choose/2, loop/1, guarded/1, wait/1, invoke/2,
         exact_apply/1, possible_apply/2, partial_apply/2,
         unresolved_apply/3]).

choose(Key, Map) ->
    case maps:find(Key, Map) of
        {ok, Value} when is_integer(Value), Value > 0 -> {positive, Value};
        {ok, Value} -> {other, Value};
        error -> missing
    end.

loop(0) -> done;
loop(N) when is_integer(N), N > 0 -> loop(N - 1).

guarded(Fun) ->
    try Fun() of
        Value -> {ok, Value}
    catch
        Class:Reason -> {Class, Reason}
    end.

wait(Timeout) ->
    receive
        {value, Value} -> Value
    after Timeout ->
        timeout
    end.

invoke(Fun, Arg) -> Fun(Arg).

exact_apply(List) ->
    Module = erlang,
    Function = length,
    apply(Module, Function, [List]).

possible_apply(Flag, Value) ->
    Function = case Flag of
        true -> abs;
        false -> round
    end,
    apply(erlang, Function, [Value]).

partial_apply(Module, Value) ->
    apply(Module, length, [Value]).

unresolved_apply(Module, Function, Args) ->
    apply(Module, Function, Args).
