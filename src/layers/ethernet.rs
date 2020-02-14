use pnet_base::MacAddr;

use super::{
    Layer,
    LayerType,
};

#[repr(u16)]
pub enum EthernetType {
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	LLC                          = 0x0000,
	IPv4                         = 0x0800,
	ARP                          = 0x0806,
	IPv6                         = 0x86DD,
	CiscoDiscovery               = 0x2000,
	NortelDiscovery              = 0x01a2,
	TransparentEthernetBridging  = 0x6558,
	Dot1Q                        = 0x8100,
	PPP                          = 0x880b,
	PPPoEDiscovery               = 0x8863,
	PPPoESession                 = 0x8864,
	MPLSUnicast                  = 0x8847,
	MPLSMulticast                = 0x8848,
	EAPOL                        = 0x888e,
	QinQ                         = 0x88a8,
	LinkLayerDiscovery           = 0x88cc,
	EthernetCTP                  = 0x9000,
}

pub struct Ethernet {
    src:  MacAddr,
    dst:  MacAddr,
    next: EthernetType,
}

impl Layer for Ethernet {
    fn name(&self) -> LayerType { todo!() }
    fn contents(&self) -> &[u8] { todo!() }
    fn payload(&self) -> &[u8] { todo!() }
    /// Return the layer as a byte array reference.
    fn bytes(&self) -> &[u8] { todo!() }
    /// Decode the layer and add it to the packet
    fn decode(&self) -> Self { todo!() }
    fn next(&self) -> LayerType { todo!() }
}


