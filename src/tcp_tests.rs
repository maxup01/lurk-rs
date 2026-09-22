use super::*;

const HEADER_LEN: usize = 20;

/// Source port 443, destination port 54321, data offset 5, PSH+ACK set,
/// window 29200. Data offset 5 means no options.
const HEADER: &[u8] = &[
    0x01, 0xbb, // src port
    0xd4, 0x31, // dst port
    0x12, 0x34, 0x56, 0x78, // sequence number
    0x9a, 0xbc, 0xde, 0xf0, // acknowledgment number
    0x50, 0x18, // data offset / reserved / flags
    0x72, 0x10, // window size
    0x1f, 0x2a, // checksum
    0x00, 0x00, // urgent pointer
];

/// A realistic SYN option set: MSS 1460, SACK permitted, NOP, window scale 7,
/// then two NOPs of padding — 12 bytes, so a data offset of 8.
const OPTIONS: &[u8] = &[
    0x02, 0x04, 0x05, 0xb4, // MSS 1460
    0x04, 0x02, // SACK permitted
    0x01, // NOP
    0x03, 0x03, 0x07, // window scale 7
    0x01, 0x01, // NOP padding
];

const PAYLOAD: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

const FIN: u16 = 0x001;
const SYN: u16 = 0x002;
const PSH: u16 = 0x008;
const ACK: u16 = 0x010;

fn header_with(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut header = HEADER.to_vec();
    header[offset..offset + bytes.len()].copy_from_slice(bytes);
    header
}

fn segment_with_options() -> Vec<u8> {
    let mut segment = header_with(12, &[0x80, 0x18]); // data offset 8
    segment.extend_from_slice(OPTIONS);
    segment.extend_from_slice(PAYLOAD);
    segment
}

#[test]
fn parses_ports() {
    let (_, header) = tcp_header(HEADER).unwrap();

    assert_eq!(header.src_port, 443);
    assert_eq!(header.dst_port, 54321);
}

#[test]
fn parses_sequence_numbers_big_endian() {
    let (_, header) = tcp_header(HEADER).unwrap();

    assert_eq!(header.sequence_number, 0x12345678);
    assert_eq!(header.acknowledgment_number, 0x9abcdef0);
}

#[test]
fn parses_trailing_scalar_fields() {
    let (_, header) = tcp_header(HEADER).unwrap();

    assert_eq!(header.window_size, 29200);
    assert_eq!(header.checksum, 0x1f2a);
    assert_eq!(header.urgent_ptr, 0);
}

#[test]
fn splits_data_offset_reserved_and_flags() {
    let segment = header_with(12, &[0x5a, 0x18]);
    let (_, header) = tcp_header(&segment).unwrap();

    assert_eq!(header.data_offset, 5);
    assert_eq!(header.reserved, 0b101);
    assert_eq!(header.flags, 0x018);
}

#[test]
fn flag_bits_land_in_the_documented_positions() {
    let (_, header) = tcp_header(HEADER).unwrap();

    assert_eq!(header.flags & ACK, ACK);
    assert_eq!(header.flags & PSH, PSH);
    assert_eq!(header.flags & SYN, 0);
    assert_eq!(header.flags & FIN, 0);
}

#[test]
fn minimum_data_offset_leaves_no_options() {
    let (remaining, header) = tcp_header(HEADER).unwrap();

    assert_eq!(header.len(), 20);
    assert!(header.options.is_empty());
    assert!(remaining.is_empty());
}

#[test]
fn parses_options_when_data_offset_exceeds_minimum() {
    let segment = segment_with_options();
    let (remaining, header) = tcp_header(&segment).unwrap();

    assert_eq!(header.data_offset, 8);
    assert_eq!(header.len(), 32);
    assert_eq!(header.options, OPTIONS);
    assert_eq!(remaining, PAYLOAD);
}

#[test]
fn payload_begins_after_the_options_not_after_the_fixed_header() {
    let segment = segment_with_options();
    let (_, packet) = tcp_packet(&segment).unwrap();

    assert_eq!(packet.payload, PAYLOAD);
}

#[test]
fn packet_without_options_parses_its_payload() {
    let mut segment = HEADER.to_vec();
    segment.extend_from_slice(PAYLOAD);

    let (_, packet) = tcp_packet(&segment[..]).unwrap();

    assert_eq!(packet.payload, PAYLOAD);
}

#[test]
fn header_only_segment_has_an_empty_payload() {
    let (_, packet) = tcp_packet(HEADER).unwrap();

    assert!(packet.payload.is_empty());
}

#[test]
fn rejects_data_offset_below_the_five_word_minimum() {
    // Offset 4 would make the options length underflow.
    assert!(tcp_header(&header_with(12, &[0x40, 0x18])).is_err());
    assert!(tcp_header(&header_with(12, &[0x00, 0x18])).is_err());
}

#[test]
fn truncated_headers_error_rather_than_panic() {
    assert!(tcp_header(&HEADER[..HEADER_LEN - 1]).is_err());
    assert!(tcp_header(&[]).is_err());
    assert!(tcp_header(&header_with(12, &[0x80, 0x18])).is_err());
}
