use byteorder::ByteOrder;
use log::*;
use std::ops::Range;
use std::fmt;


use super::error::Result;
use super::linktype::LinkType;
use super::types::{Endianness, require_bytes};

#[derive(Clone, PartialEq, Debug)]
pub struct PcapHeader {
    pub major: u16,
    pub minor: u16,
    pub timezone: Option<u32>,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: LinkType,
}


impl fmt::Display for PcapHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "MajorVersion: {:#04x}", self.major)?;
        writeln!(f, "MinorVersion: {:#04x}", self.minor)?;
        match self.timezone {
            None => writeln!(f, "Timezone: None (Should this be UTC?)")?,
            Some(i) => writeln!(f, "Timezone: {}", i)?,
        }
        writeln!(f, "SigFigs: {:#06x}", self.sigfigs)?;
        writeln!(f, "Snaplen: {:#06x}", self.snaplen)?;
        writeln!(f, "LinkType: {:?}", self.linktype)
    }
}

impl PcapHeader {
    pub fn parse<B: ByteOrder>(buf: &[u8]) -> Result<Self>{
        require_bytes(buf, 22)?;
        let tz: Option<u32> = match B::read_u32(&buf[8..12]) {
            0 => None,
            i => Some(i),
        };
        let link_type: LinkType = LinkType::from_u32(
            B::read_u32(&buf[20..24])
        );

        Ok(PcapHeader {
            major: B::read_u16(&buf[4..6]),
            minor: B::read_u16(&buf[6..8]),
            timezone: tz,
            sigfigs: B::read_u32(&buf[12..16]),
            snaplen: B::read_u32(&buf[16..20]),
            linktype: link_type,
        })
    }

    pub fn peek_endianness(buf: &[u8]) -> Result<Option<Endianness>> {
        require_bytes(buf, 4)?;
        let block = &buf[..4];
        let endianness = Endianness::check_pcap_magic(&block)?;
        Ok(Some(endianness))
    }

}

/// A record (packet) header. Each captured packet starts with this structure (any byte alignment is possible).
#[derive(Clone, PartialEq, Debug)]
pub struct Packet {
    /// ts_sec: the date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments. 
    pub ts_sec: u32,
    /// ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead! 
    pub ts_usec: u32,
    /// incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.  
    pub octets_saved: usize,
    /// orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen. 
    pub actual_len: usize,
    pub packet_data: Range<usize>,
}

impl Packet {
    pub fn parse<B: ByteOrder>(buf: &[u8]) -> Result<Self> {
        todo!()
    }
}
// impl FromBytes for Packet {}

pub trait FromBytes: Sized {
    fn parse<B: ByteOrder>(buf: &[u8]) -> Result<Self>;
}



pub trait KnownByteOrder {
    fn endianness() -> Endianness;
}


