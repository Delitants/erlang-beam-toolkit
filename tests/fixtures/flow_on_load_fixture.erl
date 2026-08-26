-module(flow_on_load_fixture).
-on_load(init/0).
-export([init/0, ready/0]).

init() ->
    persistent_term:put({?MODULE, loaded}, true),
    ok.

ready() ->
    persistent_term:get({?MODULE, loaded}, false).
