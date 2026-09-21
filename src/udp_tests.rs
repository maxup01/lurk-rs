use super::*;

const HEADER_LEN: usize = 8;

/// Source port 53 (DNS), destination port 54321, length 12, checksum 0x1f2a.
///
/// Length counts the header *and* the payload, so 12 means 4 payload bytes.
const HEADER: &[u8] = &[
    0x00, 0x35, // src port
    0xd4, 0x31, // dst port
    0x00, 0x0c, // length
    0x1f, 0x2a, // checksum
];

const PAYLOAD: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

fn header_with(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut header = HEADER.to_vec();
    header[offset..offset + bytes.len()].copy_from_slice(bytes);
    header
}

fn datagram() -> Vec<u8> {
    let mut datagram = HEADER.to_vec();
    datagram.extend_from_slice(PAYLOAD);
    datagram
}

#[test]
fn parses_fields_big_endian() {
    let (_, header) = udp_header(HEADER).unwrap();

    assert_eq!(header.src_port, 53);
    assert_eq!(header.dst_port, 54321);
    assert_eq!(header.length, 12);
    assert_eq!(header.checksum, 0x1f2a);
}

#[test]
fn header_consumes_exactly_eight_bytes() {
    let datagram = datagram();
    let (remaining, _) = udp_header(&datagram).unwrap();

    assert_eq!(remaining, PAYLOAD);
}

#[test]
fn zero_checksum_is_valid_over_ipv4() {
    // A zero checksum means "not computed", which is legal for UDP over IPv4
    // and must not be treated as a malformed datagram.
    let (_, header) = udp_header(&header_with(6, &[0x00, 0x00])).unwrap();

    assert_eq!(header.checksum, 0);
}

#[test]
fn zero_source_port_is_valid() {
    // Legal, and means the sender expects no reply.
    let (_, header) = udp_header(&header_with(0, &[0x00, 0x00])).unwrap();

    assert_eq!(header.src_port, 0);
}

#[test]
fn parses_payload() {
    let datagram = datagram();
    let (_, packet) = udp_packet(&datagram).unwrap();

    assert_eq!(packet.payload, PAYLOAD);
}

#[test]
fn header_only_datagram_has_an_empty_payload() {
    // Length 8 is the minimum legal value: header, no payload.
    let datagram = header_with(4, &[0x00, 0x08]);
    let (_, packet) = udp_packet(&datagram).unwrap();

    assert!(packet.payload.is_empty());
}

#[test]
fn payload_is_delimited_by_length_not_by_input() {
    // `length` is authoritative. Trailing bytes beyond it — Ethernet padding,
    // or a crafted datagram whose IP total_length disagrees — are not payload.
    let mut frame = datagram();
    frame.extend_from_slice(&[0x00; 6]);

    let (_, packet) = udp_packet(&frame).unwrap();

    assert_eq!(packet.payload, PAYLOAD);
}

#[test]
fn truncated_headers_error_rather_than_panic() {
    assert!(udp_header(&HEADER[..HEADER_LEN - 1]).is_err());
    assert!(udp_header(&[]).is_err());
}

#[test]
fn rejects_length_below_the_header_size() {
    // Length 4 is shorter than the header it counts, so the payload length
    // would underflow.
    assert!(udp_packet(&header_with(4, &[0x00, 0x04])).is_err());
}
