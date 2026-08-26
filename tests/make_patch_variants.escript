#!/usr/bin/env escript
%%! -noshell

main([WrapperPath, OutputDirectory]) ->
    {ok, [{beam_patch_function, 1, Metadata}]} = file:consult(WrapperPath),
    ExpectedKeys = lists:sort([module, name, arity, entry_label,
                               source_assembly_digest, owned_labels,
                               function]),
    ExpectedKeys = lists:sort(maps:keys(Metadata)),
    Module = maps:get(module, Metadata),
    Name = maps:get(name, Metadata),
    Arity = maps:get(arity, Metadata),
    Entry = maps:get(entry_label, Metadata),
    Digest = maps:get(source_assembly_digest, Metadata),
    OwnedLabels = maps:get(owned_labels, Metadata),
    {function, Name, Arity, Entry, Instructions} =
        maps:get(function, Metadata),
    true = is_atom(Module),
    true = is_list(Digest),
    64 = length(Digest),
    true = is_list(OwnedLabels),
    true = lists:member(Entry, OwnedLabels),
    write(OutputDirectory, "wrong-mfa.term",
          {beam_patch_function, 1,
           Metadata#{function =>
                         {function, deliberately_wrong_name, Arity,
                          Entry, Instructions}}}),
    write(OutputDirectory, "wrong-entry.term",
          {beam_patch_function, 1,
           Metadata#{entry_label => Entry + 1}}),
    write(OutputDirectory, "foreign-label.term",
          {beam_patch_function, 1,
           Metadata#{function =>
                         {function, Name, Arity, Entry,
                          Instructions ++ [{label, 999999}]}}}),
    write(OutputDirectory, "stale-digest.term",
          {beam_patch_function, 1,
           Metadata#{source_assembly_digest => lists:duplicate(64, $0)}}),
    io:format("source-bound function wrapper ok~n");
main(_) ->
    halt(64).

write(Directory, Name, Term) ->
    Path = filename:join(Directory, Name),
    Data = unicode:characters_to_binary(io_lib:format("~tp.~n", [Term])),
    ok = file:write_file(Path, Data, [exclusive]).
