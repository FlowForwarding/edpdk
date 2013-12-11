% Copyright (c) 2013 Tieto Global Oy
%
% Licensed to the Apache Software Foundation (ASF) under one
% or more contributor license agreements.  See the NOTICE file
% distributed with this work for additional information
% regarding copyright ownership.  The ASF licenses this file
% to you under the Apache License, Version 2.0 (the
% "License"); you may not use this file except in compliance
% with the License.  You may obtain a copy of the License at
%
% 		http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing,
% software distributed under the License is distributed on an
% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
% KIND, either express or implied.  See the License for the
% specific language governing permissions and limitations
% under the License.

-module(fwdr).

% Internal exports
-export([init/1]).
-export([start_edpdk/0]).
-export([stop/0]).

% API
-export([recv/1]).
-export([xmit/2]).
-export([fwd_pkt/2]).
-export([rule_one/4]).

start_edpdk() ->
    spawn_link(?MODULE, init, ["../bin/edpdk -c 0x3 -n 4 -- --tx=0:0:1 --rx=0:0:1"]).

stop() ->
    ?MODULE ! stop.
 
%% Internal 
init(ExtPrg) ->
    register(?MODULE, self()),
    process_flag(trap_exit, true),
    Port = open_port({spawn, ExtPrg}, [{packet, 2}, binary, exit_status]),
    loop(Port).
 
loop(Port) ->
    receive
    {call, Caller, Msg} ->
        io:format("Calling port with ~p~n", [Msg]),
        erlang:port_command(Port, term_to_binary(Msg)),
        receive
        {Port, {data, Data}} ->
			io:format("~p~n", [Data]),
            Caller ! binary_to_term(Data);
        {Port, {exit_status, Status}} when Status > 128 ->
            io:format("Port terminated with signal: ~p~n", [Status-128]),
            exit({port_terminated, Status});
        {Port, {exit_status, Status}} ->
            io:format("Port terminated with status: ~p~n", [Status]),
            exit({port_terminated, Status});
        {'EXIT', Port, Reason} ->
            exit(Reason)
        end,
        loop(Port);
    stop ->
        erlang:port_close(Port),
        exit(normal)
    end.

%% API
recv(Rx) ->
	call_port({recv, <<>>, Rx}).

xmit(Packet, Tx) ->
	call_port({xmit, Packet, Tx}).

fwd_pkt(Rx, Tx) ->
	RecvMsg = recv(Rx),
	Pkt = element(2, RecvMsg),
	case RecvMsg of
		{ok, Pkt} when is_binary(Pkt) ->
			xmit(Pkt, Tx);					
		_ -> 
			RecvMsg
	end.

rule_one(Rxa, Rxb, Txa, Txb) ->
    fwd_pkt(Rxa, Txa),
	fwd_pkt(Rxb, Txb),
	rule_one(Rxa, Rxb, Txa, Txb).

call_port(Msg) ->
    ?MODULE ! {call, self(), Msg},
    receive
    Result ->
        Result
    end.
