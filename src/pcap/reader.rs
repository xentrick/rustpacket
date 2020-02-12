use buf_redux::BufReader;
use buf_redux::policy::MinBuffered;
use byteorder::{BigEndian, LittleEndian};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::ops::Range;

use super::types::*;
use super::linktype::LinkType;
use super::error::Result;
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
    pub snaplen: u32,
    /// link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for Ethernet, see [tcpdump.org's link-layer header types](http://www.tcpdump.org/linktypes.html) page for details); this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
    pub linktype: LinkType,

    /// The size of the last packet read.
    pub last_packet_len: usize,
    pub data: Range<usize>, // todo

    pub interfaces: Vec<String>, // todo
    pub current_interface: Option<String>, // todo
}

impl<R: Read> Capture<R> {
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
            data: 0..0,

            interfaces: Vec::with_capacity(0),
            current_interface: None,
        })
    }

    /// Get next packet
    pub fn next(&mut self) -> Option<Result<PacketBody>> {
        match self.advance() {
            Err(e) => Some(Err(e)),
            Ok(()) => self.get().map(Ok),
        }
    }

    /// Parse the next packet from the pcap file.
    pub fn advance(&mut self) -> Result<()> {
        // Look at the length of the _last_ block, to see how much data to discard
        self.rdr.consume(self.last_packet_len);

        // Fill the buffer up - hopefully we'll have enough data for the next block
        let buf = self.rdr.fill_buf()?;
        if buf.is_empty() {
            self.last_packet_len = 0;
            self.finished = true;
            return Ok(())
        }

        // Parse packet header and payload
        let pkt = match self.endianness {
            Endianness::Big => Packet::parse::<BigEndian>(buf, self.nano_factor)?,
                Endianness::Little => Packet::parse::<LittleEndian>(buf, self.nano_factor)?,
        };
        self.last_packet_len = pkt.orig_len;
        self.data = pkt.range.clone();
        Ok(())
    }

    /// Peek the current packet
    ///
    /// This function is cheap, since `Packet` holds a reference to the
    /// internal buffer and no pcap data is copied.  When you're done with
    /// this packet and want to see the next one, use `advance()` to move on.
    pub fn get(&self) -> Option<PacketBody> {
        if self.finished {
            return None
        }
        println!("Range: {:#?}", &self.data);
        Some(PacketBody {
            data: &self.rdr.buffer()[self.data.clone()]
        })
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
        self.data = 0..0;
        Ok(())
    }
}
