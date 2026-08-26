-module(flow_cross_a).
-export([start/1, dynamic/2]).

start(Value) -> flow_cross_b:step(Value).
dynamic(Function, Value) -> apply(flow_cross_b, Function, [Value]).
