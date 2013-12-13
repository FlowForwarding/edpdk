edpdk
=====

A set of Erlang port commands for using Intel DPDK PMDs (Poll-Mode Drivers).  Edpdk initially provides the following commands to allow an Erlang node to receive or transmit packets through
DPDK PMDs.

**1. Run edpdk port**

    Create an Erlang port with the following command:
    
        "edpdk -c <coremask> -n 4 -- --tx=<core:port1:portN...> --rx=<core:port1:portN...>..."
        e.g. To run edpdk with 2 cores and 2 ports,
        
            "edpdk -c 0x3 -n 4 -- --tx=0:0:1 --rx=0:0:1"
            
            -c = coremask (e.g. core 1 and 2 is 0x3)
            --tx = core-port assignment
                - e.g. core 0 will transmit to port 0 & 1
            --rx = similar to --tx but receives            
            
    After successfully creating the edpdk port, one can then send the port commands specified below.

**2. Receive a packet**

    To receive a packet the following tuple must be sent:
    
    {recv, <<>>, PortNo}     
    Where,
    
        Command: recv
        Packet: <<>>
            - this is always empty since we are receiving
        Port: PortNo, the source port of the ingress packet
        
    Possible output:
    
        {ok, << packet>>} 
            - packet is received
            
        {fail, empty}
            - ingress port does not have any queued packets
    
**2.  Transmit a packet**

    To transmit a packet the following tuple must be sent:
    
    {xmit, << packet>>, PortNo}
    Where,
    
        Command: xmit
        Packet: << packet>>, the packet to be sent
        Port: PortNo, the destination port of the egress packet
        
    Possible output:
    
        {ok, queued}
            - packet is queued for transmit
        
        {fail, full_or_busy}
            - packet can't be sent right now
    

The primary goal of this specific Intel DPDK application is to achieve a "fast path" for an Erlang-based packet forwarder (e.g. LINC).  Based on an oversimplified experiment, a dumb packet forwarder (fwdr.erl) showed better packet forwarding performance over LINC when forwarding a packet with a very basic rule.  However, this experiment only tells very little about the possibility of enhancing LINC with DPDK and it should be noted.  Nevertheless, these could be a good motivation to start using DPDK PMDs when processing packets in LINC.  One quite interesting idea but still an area to explore is to level up the edpdk implementation to use Erlang NIFs or linked in drivers to eliminate overhead introduced by the port communication.  On the other hand, again this is still an area to explore ans as well test, because DPDK yet needs to be evauluated for these approaches due to the fact that it doesn't directly provide system integration facilities - if there is, it isn't a first class feature.


For more information on Intel DPDK please see the following links:


- [dpdk.org](http://dpdk.org/)
- [Intel DPDK Packet Processing Overview](http://www.intel.ph/content/dam/www/public/us/en/documents/presentation/dpdk-packet-processing-ia-overview-presentation.pdf)
~