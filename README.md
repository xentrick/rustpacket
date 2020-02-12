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
