# rustpacket

This is a clone of gopacket. However right now I just need it for legacy pcap parsing.

The pcap parsing in this is pretty much just a clone of (pcarp)[https://github.com/asayers/pcarp] since it was done really well. I created this README in 2 seconds, I will give him proper credit once I get to where I want to be.

## ToDo

- [ ] Legacy Pcap
  - [ ] Read Packets
  - [ ] Write Pcap
  - [ ] Capture live
- [ ] Pcapng integration
- [ ] Serialization/Deserialization
- [ ] Layers
- [ ] AFPacket
- [ ] PFRing
- [ ] BPF
- [ ] Stream Reassembly

## Investigate

- [ ] Verify type for Timezone/Sigfigs
- [ ] Validate legacy pcap rewind()

## Other

- [ ] Benchmarks
- [ ] Tests
  - [ ] Pcap
  - [ ] Layers
  - [ ] Pcapng
  - [ ] AFPacket
  - [ ] PFRing
  - [ ] BPF

# Modules

- layers - packet decoding 
- pcap - pcap parsing and (optional?) layer parsing
- pfring - there should already be bindings for this
- afpacket - should be bindings or we can reimplement.
- tcp stream reassembly

## Visions

- PFRing
- AFPacket
- PacketBuilder
- Packet
  - zerocopy or owned
  - iterate layers
  - parse and add layers
  - edit individual layers
    - setters all options (fuzzing, low level control)
  - Reference layer by OSI
    - Ex: `packet.ApplicationLayer()`
  - send packets
- Pcap (eventually add in PcapNg)
  - writer
  - reader
  - zerocopy
- Trait based derives?
  - Define Layer
    - Physical
    - Network
    - Transport
    - Application
    - 2,3,4,7
- Flow
  - Object with two `EndPoints`
  - Allow map()
  - Endpoint is hashtable representation of source/dest
    - Details sender and receiver of the layer of th epacket
    - Generic representation (Contains IPV4 or IPV6 example)
  - Endpoints can be combined into a flow or a flow broken into endpoints
    - `flow.endpoints()`
    - `Flow::new(src, dst)`
  - Use Flow and ENdpoint as map keys, allow equality
    - Look for packets with same src/dst net addr
    - Find all packets between UDP/TCP port ranges
      - `packet.FlowFrom(layers.UDPEndpoint(1000), ...(5000))`
        - `packet.TransportFlow() == <FlowFrom>`
          - FashHash funcitons to get non crypto hashes of their contents.
- Custom Decoder
  - `layers.RegisterLayer`
  - `impl Layer for CustomProtocol`
    - `type()`
    - `header()`
    - `payload()`
    - `parse()`
    - `nextDecoder()` - determine how ot handle next layer
- FixedDecoder
  - Specify layers beforehand if they are already known
  - MUCH FASTER
  - `SuperDuperDecoder::something(&layers.eth, &layers.ipv4, &layers.tcp)`
  - No need for allocating new packets each time. One packet with a known structure
- Serializer/Deserializer for easy parsing/sending/receiving for known types?
  
  
# Cool Stuff

 - Is it possible to implement an interface as the generic for BufWriter/BufReader?
   


# Dir Structure

- [ ] afpacket
- [ ] bin
  - [ ] tcpdump
  - [ ] file2pcap
- [ ] bpf
- [ ] layers
- [ ] parser
  - LayerDecoding
  - Packet
- [ ] pcap
- [ ] pfring
- [ ] physical/hardware/datalink
- [ ] reassembly
- [ ] util

- PacketBuilder
- Packet
