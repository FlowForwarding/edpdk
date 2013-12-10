edpdk
=====

A set of Erlang port commands for using Intel DPDK PMDs (Poll-Mode Drivers).  edpdk initially provides the following port
commands to allow an Erlang node to receive and transmit packets through DPDK PMDs.  

1. {recv, <<>>, PortNo} - Receive a packet from PortNo in the follwing formats:
   
   a. {ok, <<packet>>} 
   b. {fail, empty}
   
     
2. {xmit, <<packet>>, PortNo} - Transmit a packet to PortNo and returns a status in the following formats:
   
   a. {ok, queued}
   b. {fail, full_or_busy}
   
The driving motivation for this specific Intel DPDK support is to achieve a "fast path" for an Erlang-based packet
forwarder (e.g. soft switch).  Based on a very simple experiment, a dumb packet forwarder (fwdr.erl) showed better
packet forwarding performance over a soft switch when forwarding a packet with a very simple rule.  However, since
edpdk is implemented with Erlang ports, a packet copy from C to Erlang space plus stdin/stdout sys calls are introduced.
Nevertheless, it could be improved to use Erlang drivers or NIFs to eliminate these overheads. Yet Intel DPDK needs
to be evaluated for these approaches since it does not directly provide system integration facilities.  Integrating
Intel DPDK with Erlang VM is yet an area to explore and test.



