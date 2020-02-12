use super::error::{Error, Result};

#[derive(Clone, PartialEq, Debug, Copy)]
pub enum Endianness {
    Big,
    Little,
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

