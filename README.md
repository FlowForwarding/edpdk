edpdk
=====

A set of Erlang port commands for using Intel DPDK PMDs (Poll-Mode Drivers).  Edpdk initially
provides the following commands to allow an Erlang node to receive or transmit packets through
DPDK PMDs.

- {recv, <<>>, PortNo} - Receive a packet from PortNo with the following formats:
  
  - {ok, << packet>>}
  - {fail, empty}
  


- {xmit, << packet>>, PortNo} - Transmit a packet to PortNo and returns a status in the following formats:

    - {ok, queued}
    - {fail, full_or_busy}
    
The driving motivation for this specific Intel DPDK support is to achieve a "fast path" for an Erlang-based packet forwarder (e.g. soft switch).  Based on a very simple experiment, a dumb packet forwarder (fwdr.erl) showed better packet forwarding performance over a soft switch when forwarding a packet with a very simple rule.  However, since edpdk is implemented with Erlang ports, a packet copy from C to Erlang space plus stdin/stdout sys calls are introduced.  Nevertheless, it could be improved to use Erlang drivers or NIFs to eliminate these overheads. Yet Intel DPDK needs to be evaluated for these approaches since it does not directly provide system integration facilities.  Integrating Intel DPDK with Erlang VM is yet an area to explore and test.
 

For more information on Intel DPDK please see the following links:


- [dpdk.org](http://dpdk.org/)
- [Intel DPDK Packet Processing Overview](http://www.intel.ph/content/dam/www/public/us/en/documents/presentation/dpdk-packet-processing-ia-overview-presentation.pdf)
