/// The type of physical link backing a network interface.
/// All layers defined as seen here: https://www.tcpdump.org/linktypes.html
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum LinkType {
    /// No link layer information. A packet saved with this link layer contains a raw L3 packet
    /// preceded by a 32-bit host-byte-order AF_ value indicating the specific L3 type.
    NULL,
    /// D/I/X and 802.3 Ethernet
    ETHERNET,
    /// Experimental Ethernet (3Mb)
    EXP_ETHERNET,
    /// Amateur Radio AX.25
    AX24,
    /// Proteon ProNET Token Ring
    PRONET,
    /// Chaos
    CHAOS,
    /// IEEE 802 Networks
    TOKEN_RING,
    /// ARCNET, with BSD-style header
    ARCNET,
    /// Serial Line IP
    SLIP,
    /// Point-to-point Protocol
    PPP,
    /// FDDI
    FDDI,
    /// PPP in HDLC-like framing
    PPP_HDLC,
    /// NetBSD PPP-over-Ethernet
    PPP_ETHER,
    /// Symantec Enterprise Firewall
    SYMANTEC_FIREWALL,
    /// LLC/SNAP-encapsulated ATM
    ATM_RFC1483,
    /// Raw IP
    RAW,
    /// BSD/OS SLIP BPF header
    SLIP_BSDOS,
    /// BSD/OS PPP BPF header
    PPP_BSDOS,
    /// Cisco HDLC
    C_HDLC,
    /// IEEE 802.11 (wireless)
    IEEE802_11,
    /// Linux Classical IP over ATM
    ATM_CLIP,
    /// Frame Relay
    FRELAY,
    /// OpenBSD loopback
    LOOP,
    /// OpenBSD IPSEC enc
    ENC,
    /// ATM LANE + 802.3 (Reserved for future use)
    LANE8023,
    /// NetBSD HIPPI (Reserved for future use)
    HIPPI,
    /// NetBSD HDLC framing (Reserved for future use)
    HDLC,
    /// Linux cooked socket capture
    LINUX_SLL,
    /// Apple LocalTalk hardware
    LTALK,
    /// Acorn Econet
    ECONET,
    /// Reserved for use with OpenBSD ipfilter
    IPFILTER,
    /// OpenBSD DLT_PFLOG
    PFLOG,
    /// For Cisco-internal use
    CISCO_IOS,
    /// 802.11+Prism II monitor mode
    PRISM_HEADER,
    /// FreeBSD Aironet driver stuff
    AIRONET_HEADER,
    /// Reserved for Siemens HiPath HDLC
    HHDLC,
    /// RFC 2625 IP-over-Fibre Channel
    IP_OVER_FC,
    /// Solaris+SunATM
    SUNATM,
    /// RapidIO - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private use.
    RIO,
    /// PCI Express - Reserved as per request from Kent Dahlgren <kent@praesum.com> for private
    /// use.
    PCI_EXP,
    /// Xilinx Aurora link layer - Reserved as per request from Kent Dahlgren <kent@praesum.com>
    /// for private use.
    AURORA,
    /// 802.11 plus BSD radio header
    IEEE802_11_RADIO,
    /// Tazmen Sniffer Protocol - Reserved for the TZSP encapsulation, as per request from Chris
    /// Waters <chris.waters@networkchemistry.com> TZSP is a generic encapsulation for any other
    /// link type, which includes a means to include meta-information with the packet, e.g. signal
    /// strength and channel for 802.11 packets.
    TZSP,
    /// Linux-style headers
    ARCNET_LINUX,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLPPP,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MLFR,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ES,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_GGSN,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_MFR,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM2,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_SERVICES,
    /// Juniper-private data link type, as per request from Hannes Gredler <hannes@juniper.net>.
    /// The corresponding DLT_s are used for passing on chassis-internal metainformation such as
    /// QOS profiles, etc..
    JUNIPER_ATM1,
    /// Apple IP-over-IEEE 1394 cooked header
    APPLE_IP_OVER_IEEE1394,
    /// ???
    MTP2_WITH_PHDR,
    /// ???
    MTP2,
    /// ???
    MTP3,
    /// ???
    SCCP,
    /// DOCSIS MAC frames
    DOCSIS,
    /// Linux-IrDA
    LINUX_IRDA,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SP,
    /// Reserved for IBM SP switch and IBM Next Federation switch.
    IBM_SN,
    /// Reserved for private use
    USER0,
    /// Reserved for private use
    USER1,
    /// Reserved for private use
    USER2,
    /// Reserved for private use
    USER3,
    /// Reserved for private use
    USER4,
    /// Reserved for private use
    USER5,
    /// Reserved for private use
    USER6,
    /// Reserved for private use
    USER7,
    /// Reserved for private use
    USER8,
    /// Reserved for private use
    USER9,
    /// Reserved for private use
    USER10,
    /// Reserved for private use
    USER11,
    /// Reserved for private use
    USER12,
    /// Reserved for private use
    USER13,
    /// Reserved for private use
    USER14,
    /// Reserved for private use
    USER15,
    /// AVS monitor mode information followed by an 802.11 header.
    IEE802_11_AVS,
    /// BACnet MS/TP frames, as specified by section 9.3 MS/TP Frame Format of ANSI/ASHRAE Standard 135, BACnet® - A Data Communication Protocol for Building Automation and Control Networks, including the preamble and, if present, the Data CRC.
    BACNET_MS_TP,
    /// PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication - 0x00 for incoming and 0x01 for outgoing.
    PPP_PPPD,
    /// General Packet Radio Service Logical Link Control, as defined by 3GPP TS 04.64.
    GPRS_LLC,
    /// Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303.
    GPF_T,
    /// Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303.
    GPF_F,
    /// Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, captured via vISDN, with a LINKTYPE_LINUX_LAPD header, followed by the Q.921 frame, starting with the address field.
    LINUX_LAPD,
    /// FRF.16.1 Multi-Link Frame Relay frames, beginning with an FRF.12 Interface fragmentation format fragmentation header.
    DLT_MFR,
    /// Bluetooth HCI UART transport layer; the frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.
    BLUETOOTH_HCI_H4,
    /// USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. Only the first 48 bytes of that header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on which the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block.
    USB_LINUX,
    /// Per-Packet Information information, as specified by the Per-Packet Information Header Specification, followed by a packet with the LINKTYPE_ value specified by the pph_dlt field of that header.
    PPI,
    /// IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame.
    IEEE802_15_4_WITHFCS,
    /// Various link-layer types, with a pseudo-header, for SITA.
    SITA,
    /// Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records.
    ERF,
    /// Bluetooth HCI UART transport layer; the frame contains a 4-byte direction field, in network byte order (big-endian), the low-order bit of which is set if the frame was sent from the host to the controller and clear if the frame was received by the host from the controller, followed by an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.
    BLUETOOTH_HCI_H4_WITH_PHDR,
    /// AX.25 packet, with a 1-byte KISS header containing a type indicator.
    AX25_KISS,
    /// Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, starting with the address field, with no pseudo-header.
    LAPD,
    /// PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host"; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it's PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed.
    PPP_WITH_DIR,
    /// Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host".
    DLT_C_HDLC_WITH_DIR,
    /// Frame Relay LAPF frames, beginning with a one-byte pseudo-header with a zero value meaning "received by this host" (DCE->DTE) and a non-zero value meaning "sent by this host" (DTE->DCE), followed by an ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame.
    DLT_FRELAY_WITH_DIR,
    /// Link Access Procedure, Balanced (LAPB), as specified by ITU-T Recommendation X.25, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" (DCE->DTE) and a non-zero value meaning "sent by this host" (DTE->DCE).
    LAPB_WITH_DIR,
    /// IPMB over an I2C circuit, with a Linux-specific pseudo-header.
    IPMB_LINUX,
    /// IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame, and with the PHY-level data for the O-QPSK, BPSK, GFSK, MSK, and RCC DSS BPSK PHYs (4 octets of 0 as preamble, one octet of SFD, one octet of frame length + reserved bit) preceding the MAC-layer data (starting with the frame control field).
    IEEE802_15_4_NONASK_PHY,
    /// USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. All 64 bytes of the header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on which the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by the Section Header Block. For isochronous transfers, the ndesc field specifies the number of isochronous descriptors that follow.
    USB_LINUX_MMAPPED,
    /// Fibre Channel FC-2 frames, beginning with a Frame_Header.
    FC_2,
    /// Fibre Channel FC-2 frames, beginning an encoding of the SOF, followed by a Frame_Header, and ending with an encoding of the SOF.
    /// The encodings represent the frame delimiters as 4-byte sequences representing the corresponding ordered sets, with K28.5 represented as 0xBC, and the D symbols as the corresponding byte values; for example, SOFi2, which is K28.5 - D21.5 - D1.2 - D21.2, is represented as 0xBC 0xB5 0x55 0x55.
    FC_2_WITH_FRAME_DELIMS,
    /// Solaris ipnet pseudo-header, followed by an IPv4 or IPv6 datagram.
    IPNET,
    /// CAN (Controller Area Network) frames, with a pseudo-header followed by the frame payload.
    CAN_SOCKET_CAN,
    /// Raw IPv4; the packet begins with an IPv4 header.
    IPV4,
    /// Raw IPv6; the packet begins with an IPv6 header.
    IPV6,
    /// IEEE 802.15.4 Low-Rate Wireless Network, without the FCS at the end of the frame.
    IEEE802_15_4_NOFCS,
    /// Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence.
    DBUS,
    /// DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification.
    DVB_CI,
    /// Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010).
    MUX27010,
    /// D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs. The current version of STANAG 5066 is backwards-compatible with the 1.0.2 version, although newer versions are classified.
    STANAG_5066_D_PDU,
    /// Linux netlink NETLINK NFLOG socket log messages.
    NFLOG,
    /// Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the MAC header and ending with the FCS.
    NETANALYZER,
    /// Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS.
    NETANALYZER_TRANSPARENT,
    /// IP-over-InfiniBand, as specified by RFC 4391 section 6.
    IPOIB,
    /// MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 (see table 2-2 of section 2.4.3.2 "Transport Stream packet layer").
    MPEG_2_TS,
    /// Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester, followed by frames for the Frame Protocol as specified by 3GPP TS 25.427 for dedicated channels and 3GPP TS 25.435 for common/shared channels in the case of ATM AAL2 or UDP traffic, by SSCOP packets as specified by ITU-T Recommendation Q.2110 for ATM AAL5 traffic, and by NBAP packets for SCTP traffic.
    NG40,
    /// Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1.
    NFC_LLCP,
    /// Raw InfiniBand frames, starting with the Local Routing Header, as specified in Chapter 5 "Data packet format" of InfiniBand™ Architectural Specification Release 1.2.1 Volume 1 - General Specifications.
    INFINIBAND,
    /// SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6.
    SCTP,
    /// USB packets, beginning with a USBPcap header.
    USBPCAP,
    /// Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product, followed by a payload for one of a number of industrial control protocols.
    RTAC_SERIAL,
    /// Bluetooth Low Energy air interface Link Layer packets, in the format described in section 2.1 "PACKET FORMAT" of volume 6 of the Bluetooth Specification Version 4.0 (see PDF page 2200), but without the Preamble.
    BLUETOOTH_LE_LL,
    /// Linux Netlink capture encapsulation.
    NETLINK,
    /// Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack.
    BLUETOOTH_LINUX_MONITOR,
    /// Bluetooth Basic Rate and Enhanced Data Rate baseband packets.
    BLUETOOTH_BREDR_BB,
    /// Bluetooth Low Energy link-layer packets.
    BLUETOOTH_LE_LL_WITH_PHDR,
    /// PROFIBUS data link layer packets, as specified by IEC standard 61158-4-3, beginning with the start delimiter, ending with the end delimiter, and including all octets between them.
    PROFIBUS_DL,
    /// Apple PKTAP capture encapsulation.
    PKTAP,
    /// Ethernet-over-passive-optical-network packets, starting with the last 6 octets of the modified preamble as specified by 65.1.3.2 "Transmit" in Clause 65 of Section 5 of IEEE 802.3, followed immediately by an Ethernet frame.
    EPON,
    /// IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification. The time stamps for packets in this format must match the time stamps in the Trace Data Blocks.
    IPMI_HPM_2,
    /// Z-Wave RF profile R1 and R2 packets, as specified by ITU-T Recommendation G.9959, with some MAC layer fields moved.
    ZWAVE_R1_R2,
    /// Z-Wave RF profile R3 packets, as specified by ITU-T Recommendation G.9959, with some MAC layer fields moved.
    ZWAVE_R3,
    /// Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures.
    WATTSTOPPER_DLM,
    /// Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification.
    ISO_14443,
    /// Radio data system (RDS) groups, as per IEC 62106, encapsulated in this form.
    RDS,
    /// USB packets, beginning with a Darwin (macOS, etc.) USB header.
    USB_DARWIN,
    /// SDLC packets, as specified by Chapter 1, "DLC Links", section "Synchronous Data Link Control (SDLC)" of Systems Network Architecture Formats, GA27-3136-20, without the flag fields, zero-bit insertion, or Frame Check Sequence field, containing SNA path information units (PIUs) as the payload.
    SDLC,
    /// LoRaTap pseudo-header, followed by the payload, which is typically the PHYPayload from the LoRaWan specification.
    LORATAP,
    /// Protocol for communication between host and guest machines in VMware and KVM hypervisors.
    VSOCK,
    /// Messages to and from a Nordic Semiconductor nRF Sniffer for Bluetooth LE packets, beginning with a pseudo-header.
    NORDIC_BLE,
    /// DOCSIS packets and bursts, preceded by a pseudo-header giving metadata about the packet.
    DOCSIS31_XRA31,
    /// mPackets, as specified by IEEE 802.3br Figure 99-4, starting with the preamble and always ending with a CRC field.
    ETHERNET_MPACKET,
    /// DisplayPort AUX channel monitoring data as specified by VESA DisplayPort(DP) Standard preceeded by a pseudo-header.
    DISPLAYPORT_AUX,
    /// Linux "cooked" capture encapsulation v2.
    LINUX_SLL2,
    /// Openvizsla FPGA-based USB sniffer.
    OPENVIZSLA,
    /// Elektrobit High Speed Capture and Replay (EBHSCR) format.
    EBHSCR,
    /// Records in traces from the http://fd.io VPP graph dispatch tracer, in the the graph dispatcher trace format.
    VPP_DISPATCH,
    /// Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.
    DSA_TAG_BRCM,
    /// Ethernet frames, with a switch tag inserted before the destination address in the Ethernet header.
    DSA_TAG_BRCM_PREPEND,
    /// IEEE 802.15.4 Low-Rate Wireless Networks, with a pseudo-header containing TLVs with metadata preceding the 802.15.4 header.
    IEEE802_15_4_TAP,
    /// Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header.
    DSA_TAG_DSA,
    /// Ethernet frames, with a programmable Ethernet type switch tag inserted between the source address field and the type/length field in the Ethernet header.
    DSA_TAG_EDSA,
    /// Payload of lawful intercept packets using the ELEE protocol. The packet begins with the ELEE header; it does not include any transport-layer or lower-layer headers for protcols used to transport ELEE packets.
    ELEE,
    /// Serial frames transmitted between a host and a Z-Wave chip over an RS-232 or USB serial connection, as described in section 5 of the Z-Wave Serial API Host Application Programming Guide.
    Z_WAVE_SERIAL,
    /// USB 2.0, 1.1, or 1.0 packet, beginning with a PID, as described by Chapter 8 "Protocol Layer" of the the Universal Serial Bus Specification Revision 2.0.
    USB_2_0,
    /// Unknown link type
    UNKNOWN(u32),
}

impl LinkType {
    /// Decode LinkType from u16
    pub fn from_u32(i: u32) -> LinkType {
        match i {
            0 => LinkType::NULL,
            1 => LinkType::ETHERNET,
            2 => LinkType::EXP_ETHERNET,
            3 => LinkType::AX24,
            4 => LinkType::PRONET,
            5 => LinkType::CHAOS,
            6 => LinkType::TOKEN_RING,
            7 => LinkType::ARCNET,
            8 => LinkType::SLIP,
            9 => LinkType::PPP,
            10 => LinkType::FDDI,
            // LINKTYPE_RAW is defined as 101 in the registry but for some reason libpcap uses DLT_RAW
            // defined as 14 on OpenBSD and as 12 for other platforms for the link type. So in order to
            // reliably decode link types we need to remap those numbers as LinkType::RAW here.
            // This isn't used in legacy pcap format, only Pcapng
            12 => LinkType::RAW,
            14 => LinkType::RAW,
            50 => LinkType::PPP_HDLC,
            51 => LinkType::PPP_ETHER,
            99 => LinkType::SYMANTEC_FIREWALL,
            100 => LinkType::ATM_RFC1483,
            101 => LinkType::RAW,
            102 => LinkType::SLIP_BSDOS,
            103 => LinkType::PPP_BSDOS,
            104 => LinkType::C_HDLC,
            105 => LinkType::IEEE802_11,
            106 => LinkType::ATM_CLIP,
            107 => LinkType::FRELAY,
            108 => LinkType::LOOP,
            109 => LinkType::ENC,
            110 => LinkType::LANE8023,
            111 => LinkType::HIPPI,
            112 => LinkType::HDLC,
            113 => LinkType::LINUX_SLL,
            114 => LinkType::LTALK,
            115 => LinkType::ECONET,
            116 => LinkType::IPFILTER,
            117 => LinkType::PFLOG,
            118 => LinkType::CISCO_IOS,
            119 => LinkType::PRISM_HEADER,
            120 => LinkType::AIRONET_HEADER,
            121 => LinkType::HHDLC,
            122 => LinkType::IP_OVER_FC,
            123 => LinkType::SUNATM,
            124 => LinkType::RIO,
            125 => LinkType::PCI_EXP,
            126 => LinkType::AURORA,
            127 => LinkType::IEEE802_11_RADIO,
            128 => LinkType::TZSP,
            129 => LinkType::ARCNET_LINUX,
            130 => LinkType::JUNIPER_MLPPP,
            131 => LinkType::JUNIPER_MLFR,
            132 => LinkType::JUNIPER_ES,
            133 => LinkType::JUNIPER_GGSN,
            134 => LinkType::JUNIPER_MFR,
            135 => LinkType::JUNIPER_ATM2,
            136 => LinkType::JUNIPER_SERVICES,
            137 => LinkType::JUNIPER_ATM1,
            138 => LinkType::APPLE_IP_OVER_IEEE1394,
            139 => LinkType::MTP2_WITH_PHDR,
            140 => LinkType::MTP2,
            141 => LinkType::MTP3,
            142 => LinkType::SCCP,
            143 => LinkType::DOCSIS,
            144 => LinkType::LINUX_IRDA,
            145 => LinkType::IBM_SP,
            146 => LinkType::IBM_SN,
            147 => LinkType::USER0,
            148 => LinkType::USER1,
            149 => LinkType::USER2,
            150 => LinkType::USER3,
            151 => LinkType::USER4,
            152 => LinkType::USER5,
            153 => LinkType::USER6,
            154 => LinkType::USER7,
            155 => LinkType::USER8,
            156 => LinkType::USER9,
            157 => LinkType::USER10,
            158 => LinkType::USER11,
            159 => LinkType::USER12,
            160 => LinkType::USER13,
            161 => LinkType::USER14,
            162 => LinkType::USER15,
            163 => LinkType::IEE802_11_AVS,
            165 => LinkType::BACNET_MS_TP,
            166 => LinkType::PPP_PPPD,
            169 => LinkType::GPRS_LLC,
            170 => LinkType::GPF_T,
            171 => LinkType::GPF_F,
            177 => LinkType::LINUX_LAPD,
            182 => LinkType::DLT_MFR,
            187 => LinkType::BLUETOOTH_HCI_H4,
            189 => LinkType::USB_LINUX,
            192 => LinkType::PPI,
            195 => LinkType::IEEE802_15_4_WITHFCS,
            196 => LinkType::SITA,
            197 => LinkType::ERF,
            201 => LinkType::BLUETOOTH_HCI_H4_WITH_PHDR,
            202 => LinkType::AX25_KISS,
            203 => LinkType::LAPD,
            204 => LinkType::PPP_WITH_DIR,
            205 => LinkType::DLT_C_HDLC_WITH_DIR,
            206 => LinkType::DLT_FRELAY_WITH_DIR,
            207 => LinkType::LAPB_WITH_DIR,
            209 => LinkType::IPMB_LINUX,
            215 => LinkType::IEEE802_15_4_NONASK_PHY,
            220 => LinkType::USB_LINUX_MMAPPED,
            224 => LinkType::FC_2,
            225 => LinkType::FC_2_WITH_FRAME_DELIMS,
            226 => LinkType::IPNET,
            227 => LinkType::CAN_SOCKET_CAN,
            228 => LinkType::IPV4,
            229 => LinkType::IPV6,
            230 => LinkType::IEEE802_15_4_NOFCS,
            231 => LinkType::DBUS,
            235 => LinkType::DVB_CI,
            236 => LinkType::MUX27010,
            237 => LinkType::STANAG_5066_D_PDU,
            239 => LinkType::NFLOG,
            240 => LinkType::NETANALYZER,
            241 => LinkType::NETANALYZER_TRANSPARENT,
            242 => LinkType::IPOIB,
            243 => LinkType::MPEG_2_TS,
            244 => LinkType::NG40,
            245 => LinkType::NFC_LLCP,
            247 => LinkType::INFINIBAND,
            248 => LinkType::SCTP,
            249 => LinkType::USBPCAP,
            250 => LinkType::RTAC_SERIAL,
            251 => LinkType::BLUETOOTH_LE_LL,
            253 => LinkType::NETLINK,
            254 => LinkType::BLUETOOTH_LINUX_MONITOR,
            255 => LinkType::BLUETOOTH_BREDR_BB,
            256 => LinkType::BLUETOOTH_LE_LL_WITH_PHDR,
            257 => LinkType::PROFIBUS_DL,
            258 => LinkType::PKTAP,
            259 => LinkType::EPON,
            260 => LinkType::IPMI_HPM_2,
            261 => LinkType::ZWAVE_R1_R2,
            262 => LinkType::ZWAVE_R3,
            263 => LinkType::WATTSTOPPER_DLM,
            264 => LinkType::ISO_14443,
            265 => LinkType::RDS,
            266 => LinkType::USB_DARWIN,
            268 => LinkType::SDLC,
            270 => LinkType::LORATAP,
            271 => LinkType::VSOCK,
            272 => LinkType::NORDIC_BLE,
            273 => LinkType::DOCSIS31_XRA31,
            274 => LinkType::ETHERNET_MPACKET,
            275 => LinkType::DISPLAYPORT_AUX,
            276 => LinkType::LINUX_SLL2,
            278 => LinkType::OPENVIZSLA,
            279 => LinkType::EBHSCR,
            280 => LinkType::VPP_DISPATCH,
            281 => LinkType::DSA_TAG_BRCM,
            282 => LinkType::DSA_TAG_BRCM_PREPEND,
            283 => LinkType::IEEE802_15_4_TAP,
            284 => LinkType::DSA_TAG_DSA,
            285 => LinkType::DSA_TAG_EDSA,
            286 => LinkType::ELEE,
            287 => LinkType::Z_WAVE_SERIAL,
            288 => LinkType::USB_2_0,
            x => LinkType::UNKNOWN(x),
        }
    }
}
