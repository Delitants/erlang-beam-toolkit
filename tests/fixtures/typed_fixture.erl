-module(typed_fixture).
-export([first/1, tagged/1]).

first(Tuple) when is_tuple(Tuple) -> element(1, Tuple).
tagged({ok, Value}) -> Value;
tagged(_) -> error.
