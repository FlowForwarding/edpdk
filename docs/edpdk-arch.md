
# Edpdk Architecture


Edpdk provides Erlang-port-based API for sending and receiving packets through a fast path implementation using Intel DPDK.  The fast path implementation was accomplished by utilizing the Intel DPDK API and furthermore exposing this to pmdengine layer.  The pmdengine layer is the interface to DPDK code and as well contain common functions that configure and start ports, lcores and the DPDK main loop.  As a result of these software interactions, an aribtrary Erlang application can receive and transmit packets using the edpdk API.


### Notable Features of edpdk
    
* Configurable lcore-port topology
* Provides receive and transmit API
* Can scale with multi-core processors
* Inherits DPDK packet processing benefits
* Could be improved to use different IPC mechanisms 
* Could be improved to reside in the Erlang VM to imporove performance
    

The following is the architectural view of edpdk.
![architectural view](https://github.com/shivarammysore/edpdk/raw/master/docs/edpdk-arch.png)

