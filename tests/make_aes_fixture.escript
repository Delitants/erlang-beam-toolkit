#!/usr/bin/env escript
%%! -noshell
-mode(compile).

main([Input, PackedOutput, ExpectedOutput, Key1Path, Key2Path]) ->
    {ok, Original} = file:read_file(Input),
    {ok, Module, Chunks0} = beam_lib:all_chunks(Original),
    Chunks = [{list_to_binary(Id), Data} || {Id, Data} <- Chunks0,
              Id =/= "Dbgi", Id =/= "Abst"],
    Code = one(<<"Code">>, Chunks),
    <<CodeHeader:20/binary, CodeBody/binary>> = Code,
    LitT = one(<<"LitT">>, Chunks),
    Key1 = read_key(Key1Path),
    Key2 = read_key(Key2Path),
    ModuleBin = atom_to_binary(Module),
    IV1 = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    IV2 = <<15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0>>,
    Dbgi = envelope(ModuleBin, 1, Key1, IV1, CodeBody),
    Abst = envelope(ModuleBin, 2, Key2, IV2, LitT),
    PackedChunks0 = [case Id of
                         <<"Code">> -> {Id, CodeHeader};
                         <<"LitT">> -> {Id, <<0:32, 0:32>>};
                         _ -> {Id, Data}
                     end || {Id, Data} <- Chunks],
    PackedChunks = insert_after(<<"Code">>, {<<"Dbgi">>, Dbgi}, PackedChunks0) ++
                   [{<<"Abst">>, Abst}],
    {ok, Packed} = beam_lib:build_module(as_chunk_ids(PackedChunks)),
    {ok, Expected} = beam_lib:build_module(as_chunk_ids(Chunks)),
    ok = file:write_file(PackedOutput, Packed, [exclusive]),
    ok = file:write_file(ExpectedOutput, Expected, [exclusive]),
    ok;
main(_) -> halt(64).

one(Id, Chunks) ->
    [Value] = [Data || {ChunkId, Data} <- Chunks, ChunkId =:= Id],
    Value.

envelope(Module, Selector, Key, IV, Plain) ->
    Cipher = crypto:crypto_one_time(aes_256_ctr, Key, IV, Plain, true),
    Digest = crypto:hash(sha256, Plain),
    <<0, 6, "aes128", IV/binary, (byte_size(Module)), Module/binary,
      Selector, Digest/binary, Cipher/binary>>.

insert_after(Id, Item, [{Id, _} = Head | Rest]) -> [Head, Item | Rest];
insert_after(Id, Item, [Head | Rest]) -> [Head | insert_after(Id, Item, Rest)];
insert_after(Id, _Item, []) -> error({missing_insert_chunk, Id}).

as_chunk_ids(Chunks) -> [{binary_to_list(Id), Data} || {Id, Data} <- Chunks].

read_key(Path) ->
    {ok, Raw} = file:read_file(Path),
    Hex = string:trim(binary_to_list(Raw)),
    64 = length(Hex),
    list_to_binary([list_to_integer([A, B], 16) || [A, B] <- pairs(Hex)]).

pairs([A, B | Rest]) -> [[A, B] | pairs(Rest)];
pairs([]) -> [].
