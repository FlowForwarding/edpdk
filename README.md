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
    
This specific Intel DPDK application is primarily to achieve a "fast path" for an Erlang-based packet forwarder (e.g. a soft switch).  Based on an oversimplified experiment, a dumb packet forwarder (fwdr.erl) showed better packet forwarding performance over a soft switch when forwarding a packet with a very simple rule.  However, since edpdk is implemented with Erlang ports, a packet copy from C to Erlang space plus stdin/stdout sys calls were introduced.  Nevertheless, these could be possibly improved to use Erlang linked in drivers or NIFS to eliminate these overhead.  Intel DPDK yet needs to be evaluated for these approaches since it does not directly provide system integration facilities.  Integrating Erlang VM and Intel DPDK is still an area to explore and test.  


For more information on Intel DPDK please see the following links:


- [dpdk.org](http://dpdk.org/)
- [Intel DPDK Packet Processing Overview](http://www.intel.ph/content/dam/www/public/us/en/documents/presentation/dpdk-packet-processing-ia-overview-presentation.pdf)
