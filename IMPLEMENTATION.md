

# Parsing

- Use 8kb buffer
- BufReader
- Byteorder matching on endianess
  - `<B: ByteOrder + KnownByteOrder>`


# Feature Support

- Pcap & Pcap-ng
  - Capture
  - Write
  - Parse 
  - gzip decoding (GzDecoder wrap)
  - Zero copy
- AF_Packet
- pf_ring
- BPF (Cloudflare's wireshark librayr could help)
- Packet layers
  - Link type
  - TCP/UDP
  - SOme application layers
- Static layer decoding like gopacket. If we know what it contains, let us preallocate the buffers sizes

