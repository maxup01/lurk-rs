use super::*;

const HEADER_LEN: usize = 14;

/// Broadcast destination, unicast source, EtherType 0x0800 (IPv4), followed by
/// 16 bytes of payload — deliberately longer than the header, so an off-by-one
/// in where the payload starts produces a wrong slice rather than an empty one.
const FRAME: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
    0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, // src
    0x08, 0x00, // ethertype
    0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, // payload
    0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01,
];

#[test]
fn parses_header_fields() {
    let (_, header) = ethernet_header(FRAME).unwrap();

    assert_eq!(header.dst, [0xff; 6]);
    assert_eq!(header.src, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
}

#[test]
fn ethertype_is_read_big_endian() {
    let (_, header) = ethernet_header(FRAME).unwrap();

    assert_eq!(header.ethertype, 0x0800);
}

#[test]
fn header_consumes_exactly_fourteen_bytes() {
    let (remaining, _) = ethernet_header(FRAME).unwrap();

    assert_eq!(remaining, &FRAME[HEADER_LEN..]);
}

#[test]
fn payload_begins_immediately_after_the_header() {
    let (remaining, packet) = ethernet_packet(FRAME).unwrap();

    assert_eq!(packet.payload, &FRAME[HEADER_LEN..]);
    assert!(remaining.is_empty());
}

#[test]
fn header_only_frame_has_an_empty_payload() {
    let (_, packet) = ethernet_packet(&FRAME[..HEADER_LEN]).unwrap();

    assert!(packet.payload.is_empty());
}

#[test]
fn truncated_frames_error_rather_than_panic() {
    assert!(ethernet_header(&FRAME[..HEADER_LEN - 1]).is_err());
    assert!(ethernet_header(&FRAME[..3]).is_err());
    assert!(ethernet_header(&[]).is_err());
}
