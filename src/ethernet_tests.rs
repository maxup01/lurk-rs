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

/// Every variant, paired with the value that appears on the wire.
const KNOWN: [(EtherType, u16); 4] = [
    (EtherType::Ethernet, 0x0001),
    (EtherType::IPv4, 0x0800),
    (EtherType::ARP, 0x0806),
    (EtherType::IPv6, 0x86dd),
];

fn frame_with_ethertype(ethertype: u16) -> Vec<u8> {
    let mut frame = FRAME.to_vec();
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    frame
}

#[test]
fn parses_header_fields() {
    let (_, header) = ethernet_header(FRAME).unwrap();

    assert_eq!(header.dst, [0xff; 6]);
    assert_eq!(header.src, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
}

#[test]
fn ethertype_is_read_big_endian() {
    let (_, header) = ethernet_header(FRAME).unwrap();

    // Byte-swapped, these two bytes read 0x0008 — not a variant at all, so a
    // little-endian read now fails the parse rather than silently misreporting.
    assert_eq!(header.ethertype, EtherType::IPv4);
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

#[test]
fn every_known_ethertype_parses() {
    for (expected, wire) in KNOWN {
        let frame = frame_with_ethertype(wire);
        let (_, header) = ethernet_header(&frame).unwrap();

        assert_eq!(header.ethertype, expected, "wire value {wire:#06x}");
    }
}

#[test]
fn discriminants_match_the_conversion() {
    for (variant, wire) in KNOWN {
        assert_eq!(variant as u16, wire);
        assert_eq!(EtherType::try_from(wire), Ok(variant));
    }
}

#[test]
fn unknown_ethertypes_report_the_raw_value() {
    assert_eq!(EtherType::try_from(0x8100), Err(0x8100)); // VLAN
    assert_eq!(EtherType::try_from(0x88cc), Err(0x88cc)); // LLDP
    assert_eq!(EtherType::try_from(0x0000), Err(0x0000));
    assert_eq!(EtherType::try_from(0xffff), Err(0xffff));
}

#[test]
fn frames_with_an_unknown_ethertype_are_rejected() {
    // Current behaviour: the header parse fails outright rather than handing
    // the raw value upwards, so VLAN, LLDP and MPLS frames never reach
    // `parse_frame` and never produce a row.
    assert!(ethernet_header(&frame_with_ethertype(0x8100)).is_err());
    assert!(ethernet_header(&frame_with_ethertype(0x88cc)).is_err());
    assert!(ethernet_packet(&frame_with_ethertype(0x8100)).is_err());
}

#[test]
fn ethertype_is_two_bytes_wide() {
    // `#[repr(u16)]` is what keeps the enum layout-identical to the wire field.
    assert_eq!(size_of::<EtherType>(), 2);
}

#[test]
fn padding_is_kept_as_payload_at_this_layer() {
    // Ethernet pads short frames to a 60-byte minimum and has no length field
    // to tell padding from data, so `rest` is right here. Trimming it is IPv4's
    // job, via total_length.
    let mut frame = FRAME.to_vec();
    frame.extend_from_slice(&[0x00; 6]);

    let (_, packet) = ethernet_packet(&frame[..]).unwrap();

    assert_eq!(packet.payload.len(), frame.len() - HEADER_LEN);
}

#[test]
fn headers_compare_by_value() {
    let (_, first) = ethernet_header(FRAME).unwrap();
    let (_, again) = ethernet_header(FRAME).unwrap();
    assert_eq!(first, again);

    let arp_frame = frame_with_ethertype(0x0806);
    let (_, arp) = ethernet_header(&arp_frame).unwrap();
    assert_ne!(first, arp);
}
