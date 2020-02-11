use super::error::{Error, Result};

use super::reader::{PCAP_MAGIC_BIG, PCAP_MAGIC_LITTLE};


#[derive(Clone, PartialEq, Debug, Copy)]
pub enum Endianness {
    Big,
    Little,
}

impl Endianness {
    pub fn check_pcap_magic(buf: &[u8]) -> Result<Self> {
        let magic = &buf[0..4];

        if magic == &PCAP_MAGIC_BIG {
            return Ok(Endianness::Big)
        } else if magic == &PCAP_MAGIC_LITTLE {
            return Ok(Endianness::Little)
        }

        let mut bad_magic = [0; 4];
        bad_magic.copy_from_slice(magic);
        Err(Error::IncorrectMagicBytes(bad_magic))
    }
}

pub fn require_bytes(buf: &[u8], len: usize) -> Result<()> {
    if buf.len() < len {
        Err(Error::NotEnoughBytes {
            expected: len,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

