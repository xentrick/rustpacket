use buf_redux::BufReader;
use buf_redux::policy::MinBuffered;
use byteorder::{BigEndian, LittleEndian};
use log::*;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::ops::Range;

use super::types::*;
use super::linktype::LinkType;
use super::error::{Error, Result};
use super::pcap::{Packet, PcapHeader};

const BUF_CAPACITY: usize = 10_000_000;
const DEFAULT_MIN_BUFFERED: usize = 8 * (1 << 10);

pub const PCAP_MAGIC_BIG: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
pub const PCAP_MAGIC_LITTLE: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];

// const magicGzip1: u8 = 0x1f;
// const magicGzip2: u8 = 0x8b;

// #[allow(dead_code)]
// pub struct PcapReader {
//     r: String, // Reader
//     byte_order: u8,
//     nanosecs_factor: u32,
//     major_version: u16,
//     version_minor: u16,
//     // timezone
//     // sigfigs
//     snaplen:  u32,
//     link_type: String,
//     buf: [u8; 16],
//     packet_buf: Vec<u8>,
//     finished: bool,
//     packet_number: usize,
//     pos: usize,
// }

pub struct Capture<R> {
    pub rdr: BufReader<R, MinBuffered>,
    pub finished: bool,
    pub endianness: Endianness,

    pub major_version: u16,
    pub minor_version: u16,

    pub timezone: Option<u32>,
    pub sigfigs: u32,

    pub snaplen: u32,
    pub linktype: LinkType,

    pub last_packet_len: usize,
    pub data: Range<usize>, // todo

    pub interfaces: Vec<String>, // todo
    pub current_interface: Option<String>, // todo
}

impl<R: Read> Capture<R> {
    pub fn new(rdr: R) -> Result<Capture<R>> {
        let mut reader = BufReader::with_capacity(BUF_CAPACITY, rdr)
            .set_policy(MinBuffered(DEFAULT_MIN_BUFFERED));
        let byteorder = PcapHeader::peek_endianness(reader.fill_buf()?)?
            .ok_or(Error::MalformedHeader)?;

        println!("ByteOrder: {:#?}", byteorder);

        let header: PcapHeader = match byteorder {
            Endianness::Big => PcapHeader::parse::<BigEndian>(reader.fill_buf()?)?,
            Endianness::Little => PcapHeader::parse::<LittleEndian>(reader.fill_buf()?)?,
        };

        println!("{}", header);

        Ok(Capture {
            rdr: reader,
            finished: false,
            endianness: byteorder,

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
    pub fn next(&mut self) -> Option<Result<Packet>> {
        match self.advance() {
            Err(e) => Some(Err(e)),
            Ok(()) => None,
            // Ok(()) => self.get().map(Ok),
        }
    }

    /// Parse the next packet from the pcap file.
    pub fn advance(&mut self) -> Result<()> {
        loop {
            // Look at the length of the _last_ block, to see how much data to discard
            self.rdr.consume(self.last_packet_len);

            // Fill the buffer up - hopefully we'll have enough data for the next block
            let buf = self.rdr.fill_buf()?;
            if buf.is_empty() {
                self.last_packet_len = 0;
                self.finished = true;
                return Ok(())
            }

            let packet: Packet = match self.endianness {
                Endianness::Big => Packet::parse::<BigEndian>(buf)?,
                Endianness::Little => Packet::parse::<LittleEndian>(buf)?,
            };
            self.last_packet_len = packet.actual_len;

            todo!()
        }
    }

    pub fn get() {
        todo!()
    }
}

