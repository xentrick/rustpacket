use buf_redux::BufReader;
use buf_redux::policy::MinBuffered;
use byteorder::{BigEndian, LittleEndian};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::ops::Range;

use super::types::*;
use super::linktype::LinkType;
use super::error::{Result, Error};
use super::pcap::{Packet, PcapHeader, PacketBody};

const BUF_CAPACITY: usize = 10_000_000;
const DEFAULT_MIN_BUFFERED: usize = 8 * (1 << 10);

pub const MAGIC_NANO_SECONDS_BIG: [u8; 4] = [0xA1, 0xB2, 0x3C, 0x4D];
pub const MAGIC_NANO_SECONDS_LITTLE: [u8; 4] = [0x4D, 0x3C, 0xB2, 0xA1];
pub const MAGIC_MICRO_SECONDS_BIG: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
pub const MAGIC_MICRO_SECONDS_LITTLE: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];

pub struct Capture<R> {
    /// The reader used to parse the file.
    rdr: BufReader<R, MinBuffered>,
    /// Status of reading the capture file.
    pub finished: bool,

    /// The byte order, Big or Little. Based on the first 4 magic bytes of the pcap.
    pub endianness: Endianness,
    /// The nano second factor of the pcap based on the first 4 magic bytes of the pcap.
    pub nano_factor: u32,

    /// The major version number of this file format (current major version is 2).
    pub major_version: u16,
    /// The minor version number of this file format (current minor version is 4).
    pub minor_version: u16,

    /// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
    /// Other libraries such as "gopacket" have ignored timezone and sigfigs but I see no reason not to include it.
    pub timezone: i32, // What is the actual type here...
    /// sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.
    pub sigfigs: Option<usize>, // What is the actual type here...

    /// The "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below.
    pub snaplen: usize,
    /// link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for Ethernet, see [tcpdump.org's link-layer header types](http://www.tcpdump.org/linktypes.html) page for details); this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
    pub linktype: LinkType,

    /// The size of the last packet read.
    pub last_packet_len: usize,
    pub data_range: Range<usize>,

    pub interfaces: Vec<String>, // todo
    pub current_interface: Option<String>, // todo
}

impl<'p, R: Read> Capture<R> {
    pub fn new(rdr: R) -> Result<Capture<R>> {
        let mut reader = BufReader::with_capacity(BUF_CAPACITY, rdr)
            .set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));

        let (byteorder, factor): (Endianness, u32) = PcapHeader::peek_endianness(reader.fill_buf()?)?;

        let header: PcapHeader = match byteorder {
            Endianness::Big => PcapHeader::parse::<BigEndian>(reader.fill_buf()?)?,
            Endianness::Little => PcapHeader::parse::<LittleEndian>(reader.fill_buf()?)?,
        };

        // Consume the length of the header
        reader.consume(24);
        println!("ByteOrder: {:#?}", &byteorder);
        println!("{}", &header);


        Ok(Capture {
            rdr: reader,
            finished: false,
            endianness: byteorder,

            nano_factor: factor,

            major_version: header.major,
            minor_version: header.minor,

            timezone: header.timezone,
            sigfigs: header.sigfigs,

            snaplen: header.snaplen,
            linktype: header.linktype,

            last_packet_len: 0,
            data_range: 0..0,

            interfaces: Vec::with_capacity(0),
            current_interface: None,
        })
    }

    /// Get next packet
    pub fn next(&'p mut self) -> Result<Option<Packet<'p>>> {
        if self.finished {
            return Ok(None)
        }
        self.advance()
    }

    /// Parse the next packet from the pcap file.
    pub fn advance(&'p mut self) -> Result<Option<Packet<'p>>> {
        // Look at the length of the _last_ block, to see how much data to discard
        self.rdr.consume(self.last_packet_len);

        // Fill the buffer up - hopefully we'll have enough data for the next block
        let buf = self.rdr.fill_buf()?;
        if buf.is_empty() {
            self.last_packet_len = 0;
            self.finished = true;
            return Ok(None)
        }

        // Parse packet header and payload
        let pkt: Packet<'p> = match self.endianness {
            Endianness::Big => Packet::parse::<BigEndian>(buf, self.nano_factor)?,
            Endianness::Little => Packet::parse::<LittleEndian>(buf, self.nano_factor)?,
        };

        self.last_packet_len = pkt.orig_len.clone();
        self.data_range = pkt.range.clone();
        println!("next() &pkt: {:p}", pkt.payload);

        // Verify snaplen and packet length match up. If we want to bypass this error, we can manually set the snaplength.
        if pkt.incl_len > self.snaplen {
            return Err(
                Error::SnapLenExceeded{
                    caplen: pkt.incl_len,
                    snaplen: self.snaplen
                })
        }

        Ok(Some(pkt))
    }

    /// Peek the current packet payload
    ///
    /// This function is cheap, since `Packet` holds a reference to the
    /// internal buffer and no pcap data is copied.  When you're done with
    /// this packet and want to see the next one, use `advance()` to move on.
    pub fn get(&self) -> Option<PacketBody> {
        if self.finished {
            return None
        }
        println!("Range: {:#?}", &self.data_range);
        Some(PacketBody {
            data: &self.rdr.buffer()[self.data_range.clone()]
        })
    }

    /// SetSnaplen sets the snapshot length of the capture file.
    ///
    /// This is useful when a pcap file contains packets bigger than then snaplen.
    /// Pcapgo will error when reading packets bigger than snaplen, then it dumps those
    /// packets and reads the next 16 bytes, which are part of the "faulty" packet's payload, but pcapgo
    /// thinks it's the next header, which is probably also faulty because it's not really a packet header.
    /// This can lead to a lot of faulty reads.
    ///
    /// The SetSnaplen function can be used to set a bigger snaplen to prevent those read errors.
    ///
    /// This snaplen situation can happen when a pcap writer doesn't truncate packets to the snaplen size while writing packets to file.
    /// E.g. In Python, dpkt.pcap.Writer sets snaplen by default to 1500 (https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.pcap.Writer)
    /// but doesn't enforce this when writing packets (https://dpkt.readthedocs.io/en/latest/_modules/dpkt/pcap.html#Writer.writepkt).
    /// When reading, tools like tcpdump, tcpslice, mergecap and wireshark ignore the snaplen and use
    /// their own defined snaplen.
    /// E.g. When reading packets, tcpdump defines MAXIMUM_SNAPLEN (https://github.com/the-tcpdump-group/tcpdump/blob/6e80fcdbe9c41366df3fa244ffe4ac8cce2ab597/netdissect.h#L290)
    /// and uses it (https://github.com/the-tcpdump-group/tcpdump/blob/66384fa15b04b47ad08c063d4728df3b9c1c0677/print.c#L343-L358).
    ///
    /// For further reading:
    ///  - https://github.com/the-tcpdump-group/tcpdump/issues/389
    ///  - https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8808
    ///  - https://www.wireshark.org/lists/wireshark-dev/201307/msg00061.html
    ///  - https://github.com/wireshark/wireshark/blob/bfd51199e707c1d5c28732be34b44a9ee8a91cd8/wiretap/pcap-common.c#L723-L742
    ///    - https://github.com/wireshark/wireshark/blob/f07fb6cdfc0904905627707b88450054e921f092/wiretap/libpcap.c#L592-L598
    ///    - https://github.com/wireshark/wireshark/blob/f07fb6cdfc0904905627707b88450054e921f092/wiretap/libpcap.c#L714-L727
    ///  - https://github.com/the-tcpdump-group/tcpdump/commit/d033c1bc381c76d13e4aface97a4f4ec8c3beca2
    ///  - https://github.com/the-tcpdump-group/tcpdump/blob/88e87cb2cb74c5f939792171379acd9e0efd8b9a/netdissect.h#L263-L290
    pub fn set_snaplen(&mut self, len: usize) {
        self.snaplen = len;
    }
}

impl<R: Read + Seek> Capture<R> {
    /// Rewind to the beginning of the pcapng file.
    /// todo()!
    pub fn rewind(&mut self) -> Result<()> {
        self.rdr.seek(SeekFrom::Start(0))?;
        self.rdr.fill_buf()?;
        self.finished = false;
        self.last_packet_len = 0;
        self.data_range = 0..0;
        Ok(())
    }
}
