use crate::packet::Flow;

mod ethernet;


/// Layer represents a single decoded packet layer (using either the
/// OSI or TCP/IP definition of a layer).  When decoding, a packet's data is
/// broken up into a number of layers.  The caller may call name() to
/// figure out which type of layer they've received from the packet.  Optionally,
/// they may then use a type assertion to get the actual layer type for deep
/// inspection of the data.
pub trait Layer {
    fn name(&self) -> LayerType;
    fn contents(&self) -> &[u8];
    fn payload(&self) -> &[u8];
    /// Return the layer as a byte array reference.
    fn bytes(&self) -> &[u8];
    /// Decode the layer and add it to the packet
    fn decode(&self) -> Self;
    fn next(&self) -> LayerType;
    // fn can_decode(&self) -> bool;
    // fn string() -> impl fmt::Display for this
}

pub type LayerType = i64;

/// This is basically just a layer but we should implement additional traits?
/// Ipv4/Ipv6
pub trait Fragment<P> {
    fn reassemble(&self);
}

/// LinkLayer is the packet layer corresponding to TCP/IP layer 1 (OSI layer 2)
pub trait LinkLayer {
    /// Return the flow direction and endpoints
    fn flow(&self) -> dyn Flow;
}

pub trait NetworkLayer {
    fn flow(&self) -> dyn Flow;
}

pub trait TransportLayer {
    fn payload(&self) -> &[u8];
}

pub trait ApplicationLayer {}
