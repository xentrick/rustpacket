use std::io::{BufReader, Read};
use std::fs::File;

use rustpacket::pcap::reader::Capture;
use rustpacket::pcap::linktype::LinkType;
use rustpacket::pcap::types::Endianness;

fn file_to_capture(src: &str) -> Capture<File> {
    let file = File::open(src)
        .expect("Unable to open test file. Is it missing?");
    let pcap = Capture::new(file)
        .expect("Unable to create capture");
    pcap
}

#[test]
fn pcap_capture() {
    let file = File::open("tests/data/ethernet_http_single.pcap")
        .expect("Unable to open test file. Is it missing?");
    let pcap = Capture::new(file);
    assert!(pcap.is_ok())
}

#[test]
fn pcap_big_endian() {
    let pcap = file_to_capture("tests/data/nlmon-big.pcap");
    assert_eq!(pcap.endianness, Endianness::Big)
}


#[test]
fn pcap_little_endian() {
    let pcap = file_to_capture("tests/data/ethernet_http_single.pcap");
    assert_eq!(pcap.endianness, Endianness::Little)
}

#[test]
fn pcap_header() {
    let pcap = file_to_capture("tests/data/ethernet_http_single.pcap");
    assert_eq!(pcap.endianness, Endianness::Little);
    assert_eq!(pcap.major_version, 0x02);
    assert_eq!(pcap.minor_version, 0x04);
    assert_eq!(pcap.timezone, 0x0);
    assert_eq!(pcap.sigfigs, None);
    assert_eq!(pcap.snaplen, 0xffff);
    assert_eq!(pcap.linktype, LinkType::ETHERNET);
}

#[test]
fn pcap_next() {
    let mut pcap = file_to_capture("tests/data/ethernet_http_single.pcap");
    assert_eq!(pcap.major_version, 0x02);
    assert_eq!(pcap.minor_version, 0x04);
    assert_eq!(pcap.timezone, 0x0);
    assert_eq!(pcap.sigfigs, None);
    assert_eq!(pcap.snaplen, 0xffff);
    assert_eq!(pcap.linktype, LinkType::ETHERNET);
    let payload = pcap.next()
        .expect("Next packet not available when it should be...")
        .expect("Error parsing...");
    // Fix this with an ethernet layer, but this is a raw parse for now
    assert_eq!(payload.data[0..6], [0xfe, 0xff, 0x20, 0x00, 0x01, 0x00])
}

/// This tests a pcap that has incomplete data due to a small snaplen.
#[test]
fn pcap_truncated() {
    let mut pcap = file_to_capture("tests/data/http_ok_truncated.pcap");
    assert_eq!(pcap.endianness, Endianness::Little);
    assert_eq!(pcap.major_version, 0x02);
    assert_eq!(pcap.minor_version, 0x04);
    assert_eq!(pcap.timezone, 0x0);
    assert_eq!(pcap.sigfigs, None);
    assert_eq!(pcap.snaplen, 0xffff);
    assert_eq!(pcap.linktype, LinkType::ETHERNET);
    let payload = pcap.next();
}
