use std::result;
use std::fmt;
use std::io;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IncorrectMagicBytes([u8; 4]),
    NotEnoughBytes { expected: usize, actual: usize },
    MalformedHeader,
    BlockLengthMismatch,
    BlockLengthTooShort,
    WrongOptionLen(usize),
    OptionsAfterEnd,
    ResolutionTooHigh,
    IO(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            IncorrectMagicBytes(x) => write!(f, "Didn't understand magic number {:?}", x),
            NotEnoughBytes { expected, actual } => write!(
                f,
                "Not enough bytes (expected {}, saw {})",
                expected, actual
            ),
            MalformedHeader => write!(f, "There was an issue parsing the pcap header."),
            BlockLengthMismatch => write!(f, "Block's start and end lengths don't match"),
            BlockLengthTooShort => write!(f, "Block length must be at least 12 bytes"),
            WrongOptionLen(x) => write!(f, "option_len for if_tsresol should be 1 but got {}", x),
            OptionsAfterEnd => write!(f, "There were more options after an option with type 0"),
            ResolutionTooHigh => write!(f, "This timestamp resolution won't fit into a u32"),
            IO(x) => write!(f, "IO error: {}", x),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(ref x) => Some(x),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(x: io::Error) -> Error {
        Error::IO(x)
    }
}
