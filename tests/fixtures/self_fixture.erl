-module(self_fixture).
-export([id/0]).

id() -> self().
