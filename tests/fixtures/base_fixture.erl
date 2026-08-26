-module(beam_patch_fixture).
-export([value/0, echo/1, static_apply/0, known_fun/0, dynamic_apply/2,
         partial_apply/1, branch_apply/1, dynamic_fun_call/1,
         fully_dynamic_apply/2, beam_apply/3, beam_apply_last/3,
         local_target/1, local_call/1, local_tail_call/1, self_value/0]).

value() -> original_value.
echo(Value) -> {ok, Value}.
static_apply() ->
    Module = erlang,
    Function = length,
    Arguments = [[one, two]],
    apply(Module, Function, Arguments).
known_fun() ->
    Function = fun echo/1,
    apply(Function, [probe]).
dynamic_apply(Module, Function) -> apply(Module, Function, [[]]).
partial_apply(Function) -> apply(erlang, Function, [[]]).
branch_apply(Flag) ->
    {Module, Function} = case Flag of
        true -> {erlang, length};
        false -> {erlang, hd}
    end,
    apply(Module, Function, [[one]]).
dynamic_fun_call(Function) -> Function(probe).
fully_dynamic_apply(Function, Arguments) -> apply(Function, Arguments).
beam_apply(Module, Function, Argument) ->
    Result = Module:Function(Argument),
    {ok, Result}.
beam_apply_last(Module, Function, Argument) -> Module:Function(Argument).
local_target(Value) -> {local_target, Value}.
local_call(Value) ->
    Result = local_target(Value),
    {local_call, Result}.
local_tail_call(Value) -> local_target(Value).
self_value() -> self().
