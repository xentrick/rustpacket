use byteorder::ByteOrder;
use chrono::NaiveDateTime;
use std::ops::Range;
use std::fmt;

use super::error::{Error, Result};
use super::linktype::LinkType;
use super::types::{Endianness, require_bytes};
use super::reader::{
    MAGIC_NANO_SECONDS_LITTLE,
    MAGIC_NANO_SECONDS_BIG,
    MAGIC_MICRO_SECONDS_LITTLE,
    MAGIC_MICRO_SECONDS_BIG,
};

/// An internal structure that is eventually converted into `Capture`
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct PcapHeader {
    pub major: u16,
    pub minor: u16,
    pub timezone: i32,
    pub sigfigs: Option<usize>,
    pub snaplen: u32,
    pub linktype: LinkType,
}


impl fmt::Display for PcapHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "MajorVersion: {:#04x}", self.major)?;
        writeln!(f, "MinorVersion: {:#04x}", self.minor)?;
        match self.timezone {
            0 => writeln!(f, "Timezone: GMT (UTC)")?,
            i => writeln!(f, "Timezone: {}", i)?,
        }
        match self.sigfigs {
            None => writeln!(f, "SigFigs: None (Should this be UTC?)")?,
            Some(i) => writeln!(f, "SigFigs: {}", i)?,
        }
        writeln!(f, "Snaplen: {:#06x}", self.snaplen)?;
        writeln!(f, "LinkType: {:?}", self.linktype)
    }
}

impl PcapHeader {
    /// Parse the header of a legacy pcap file. This will only look at the first 24 bytes.
    /// ```c
    /// typedef struct pcap_hdr_s {
    ///         guint32 magic_number;   /* magic number */
    ///         guint16 version_major;  /* major version number */
    ///         guint16 version_minor;  /* minor version number */
    ///         gint32  thiszone;       /* GMT to local correction */
    ///         guint32 sigfigs;        /* accuracy of timestamps */
    ///         guint32 snaplen;        /* max length of captured packets, in octets */
    ///         guint32 network;        /* data link type */
    /// } pcap_hdr_t;
    /// ```
    pub fn parse<B: ByteOrder>(buf: &[u8]) -> Result<Self>{
        require_bytes(buf, 24)?;
        // Read timezone metadata
        let tz: i32 = B::read_i32(&buf[8..12]);

        // Read sigfigs
        let sig: Option<usize> = match B::read_u32(&buf[12..16]) {
            0 => None,
            i => Some(i as usize),
        };
        // Read the physical link type into `LinkType` enum.
        let link_type: LinkType = LinkType::from_u32(
            B::read_u32(&buf[20..24])
        );

        Ok(PcapHeader {
            major: B::read_u16(&buf[4..6]),
            minor: B::read_u16(&buf[6..8]),
            timezone: tz,
            sigfigs: sig,
            snaplen: B::read_u32(&buf[16..20]),
            linktype: link_type,
        })
    }

    /// Verify that the header magic is valid and return the endianness and nano second factor of the pcap file.
    pub fn peek_endianness(buf: &[u8]) -> Result<(Endianness, u32)> {
        require_bytes(buf, 4)?;
        let magic = &buf[..4];

        if magic == &MAGIC_NANO_SECONDS_LITTLE {
            return Ok((Endianness::Little, 1))
        } else if magic == &MAGIC_NANO_SECONDS_BIG {
            return Ok((Endianness::Big, 1))
        } else if magic == &MAGIC_MICRO_SECONDS_LITTLE {
            return Ok((Endianness::Little, 1000))
        } else if magic == &MAGIC_MICRO_SECONDS_BIG {
            return Ok((Endianness::Big, 1000))
        }

        let mut bad_magic = [0; 4];
        bad_magic.copy_from_slice(magic);
        Err(Error::IncorrectMagicBytes(bad_magic))
    }

}

/// A record (packet) header. Each captured packet starts with this structure (any byte alignment is possible).
#[derive(Clone, PartialEq, Debug)]
pub struct Packet<'a> {
    /// The date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UNIX time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
    pub ts_sec: u32,
    /// In regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead!
    pub ts_usec: u32,
    pub arrival: NaiveDateTime,
    /// incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
    pub incl_len: usize,
    /// orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
    pub orig_len: usize,
    /// Determines if the packet has been truncated from it's original size. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
    pub truncated: bool,
    /// Saved packet data
    pub range: Range<usize>,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse<B: ByteOrder>(buf: &'a [u8], factor: u32) -> Result<Packet<'a>> {
        // Looks like the pcap is truncated. Skip the rest.
        require_bytes(buf, 16)?;

        // Parse ts_sec and ts_usec as u32 per the spec
        // instead of i64 for NaiveDateTime. This probably
        // doesn't matter at all but I like following the rules.
        let sec = B::read_u32(&buf[..4]);
        // Multiply by the factor determined from the pcap magic
        // to get accurate `NaiveDateTime`. This is UTC and should
        // be adjusted in regards to the timezone in the `PcapHeader`
        // to display local time.
        let ms = B::read_u32(&buf[4..8]) * factor;

        // Preconvert to date time. I thought about not storing ts_sec
        // and ts_usec but for later on I'd like to allow lower level
        // control over the pcap data.
        let dt = NaiveDateTime::from_timestamp(sec.into(), ms);

        let available = B::read_u32(&buf[8..12]) as usize;
        let actual = B::read_u32(&buf[12..16]) as usize;

        // Verify there are enough bytes available in the packet...
        require_bytes(buf, 16 + available)?;

        let frag: bool = if available != actual{
            true
        } else {
            false
        };

        Ok(Packet {
            ts_sec: sec,
            ts_usec: ms,
            arrival: dt,
            incl_len: available,
            orig_len: actual,
            truncated: frag,
            range: 16..16 + available,
            payload: &buf[16..16 + available],
        })
    }
}
// impl FromBytes for Packet {}

pub trait FromBytes: Sized {
    fn parse<B: ByteOrder>(buf: &[u8]) -> Result<Self>;
}



pub trait KnownByteOrder {
    fn endianness() -> Endianness;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketBody<'a> {
    pub data: &'a [u8],
}


