-module(flow_cross_b).
-export([step/1, even/1, odd/1]).

step(Value) when is_integer(Value) -> even(Value).

even(0) -> true;
even(N) -> odd(N - 1).

odd(0) -> false;
odd(N) -> even(N - 1).
