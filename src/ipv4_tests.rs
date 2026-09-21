use super::*;

const HEADER_LEN: usize = 20;

/// Version 4, IHL 5, DSCP 46 / ECN 1, total length 24, DF set, fragment
/// offset 0, TTL 64, protocol 6 (TCP), 192.168.0.1 -> 192.168.0.199.
///
/// Total length 24 with a 20-byte header means exactly 4 bytes of payload.
const HEADER: &[u8] = &[
    0x45, 0xb9, 0x00, 0x18, // version/ihl, dscp/ecn, total length
    0x1c, 0x46, 0x40, 0x00, // identification, flags/fragment offset
    0x40, 0x06, 0xb1, 0xe6, // ttl, protocol, checksum
    0xc0, 0xa8, 0x00, 0x01, // src
    0xc0, 0xa8, 0x00, 0xc7, // dst
];

const PAYLOAD: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

fn header_with(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut header = HEADER.to_vec();
    header[offset..offset + bytes.len()].copy_from_slice(bytes);
    header
}

#[test]
fn splits_version_and_ihl() {
    let (_, header) = ipv4_header(HEADER).unwrap();

    // Both live in byte 0: masking without shifting would give 0x40 and 0.
    assert_eq!(header.version, 4);
    assert_eq!(header.ihl, 5);
}

#[test]
fn splits_dscp_and_ecn() {
    let (_, header) = ipv4_header(HEADER).unwrap();

    // Byte 1 is 0xb9 = 0b101110_01.
    assert_eq!(header.dscp, 46);
    assert_eq!(header.ecn, 1);
}

#[test]
fn splits_flags_and_fragment_offset() {
    let fragmented = header_with(6, &[0x20, 0x85]);
    let (_, header) = ipv4_header(&fragmented).unwrap();

    assert_eq!(header.flags, 0b001);
    assert_eq!(header.fragment_offset, 133);
}

#[test]
fn parses_scalar_fields_big_endian() {
    let (_, header) = ipv4_header(HEADER).unwrap();

    assert_eq!(header.total_length, 24);
    assert_eq!(header.identification, 0x1c46);
    assert_eq!(header.ttl, 64);
    assert_eq!(header.protocol, 6);
    assert_eq!(header.header_checksum, 0xb1e6);
}

#[test]
fn parses_addresses() {
    let (_, header) = ipv4_header(HEADER).unwrap();

    assert_eq!(header.src, Ipv4Addr::new(192, 168, 0, 1));
    assert_eq!(header.dst, Ipv4Addr::new(192, 168, 0, 199));
}

#[test]
fn reports_header_and_payload_lengths() {
    let (_, header) = ipv4_header(HEADER).unwrap();

    assert_eq!(header.len(), 20);
    assert_eq!(header.payload_len(), 4);
}

#[test]
fn minimum_ihl_leaves_no_options() {
    let (remaining, header) = ipv4_header(HEADER).unwrap();

    assert!(header.options.is_empty());
    assert_eq!(remaining.len(), 0);
}

#[test]
fn parses_options_when_ihl_exceeds_minimum() {
    let mut packet = header_with(0, &[0x46]);
    packet.extend_from_slice(&[0x94, 0x04, 0x00, 0x00]); // router alert
    packet.extend_from_slice(PAYLOAD);

    let (remaining, header) = ipv4_header(&packet).unwrap();

    assert_eq!(header.len(), 24);
    assert_eq!(header.options, &[0x94, 0x04, 0x00, 0x00]);
    assert_eq!(remaining, PAYLOAD);
}

#[test]
fn rejects_ihl_below_the_five_word_minimum() {
    assert!(ipv4_header(&header_with(0, &[0x44])).is_err());
    assert!(ipv4_header(&header_with(0, &[0x40])).is_err());
}

#[test]
fn truncated_headers_error_rather_than_panic() {
    assert!(ipv4_header(&HEADER[..HEADER_LEN - 1]).is_err());
    assert!(ipv4_header(&[]).is_err());

    // IHL claims options that the input does not actually contain.
    assert!(ipv4_header(&header_with(0, &[0x46])).is_err());
}

#[test]
fn packet_payload_excludes_ethernet_padding() {
    let mut frame = HEADER.to_vec();
    frame.extend_from_slice(PAYLOAD);
    frame.extend_from_slice(&[0x00; 6]); // padding

    let (_, packet) = ipv4_packet(&frame[..]).unwrap();

    assert_eq!(packet.payload, PAYLOAD);
}
