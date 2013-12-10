%   BSD LICENSE
% 
%   Copyright(c) 2013 Tieto Global Oy. All rights reserved.
%   All rights reserved.
% 
%   Redistribution and use in source and binary forms, with or without
%   modification, are permitted provided that the following conditions
%   are met:
% 
%     * Redistributions of source code must retain the above copyright
%       notice, this list of conditions and the following disclaimer.
%     * Redistributions in binary form must reproduce the above copyright
%       notice, this list of conditions and the following disclaimer in
%       the documentation and/or other materials provided with the
%       distribution.
%     * Neither the name of Intel Corporation nor the names of its
%       contributors may be used to endorse or promote products derived
%       from this software without specific prior written permission.
% 
%   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
%   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
