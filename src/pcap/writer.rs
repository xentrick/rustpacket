use std::io::BufWriter;

// The magic bytes for writing a pcap. We will be using `MAGIC_MICRO_SECONDS_BIG` as the default
pub const MAGIC_NANO_SECONDS_BIG: [u8; 4] = [0xA1, 0xB2, 0x3C, 0x4D];
pub const MAGIC_NANO_SECONDS_LITTLE: [u8; 4] = [0x4D, 0x3C, 0xB2, 0xA1];
pub const MAGIC_MICRO_SECONDS_BIG: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
pub const MAGIC_MICRO_SECONDS_LITTLE: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];

pub struct PcapWriter<R> {
    /// When reading we use the `buf_redux` crate but I don't see a need it's `BufWriter` here. Let's stick with `std` for longevity unless there is a good argument for the former.
    w: BufWriter<R>
}
