use super::*;

const HEADER_LEN: usize = 4;

/// The four bytes at offset 4..8 — the part whose meaning depends on the type.
/// Shared across the tests below so the same bytes can be shown to parse four
/// different ways.
const REST_OF_HEADER: &[u8] = &[0x12, 0x34, 0x56, 0x78];

/// Whatever follows offset 8: echo data, or a quoted packet.
const TRAILING: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

const TARGET: &[u8] = &[
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

const DESTINATION: &[u8] = &[
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
];

/// Source Link-Layer Address option: type 1, length 1 (meaning 8 bytes).
const OPTIONS: &[u8] = &[0x01, 0x01, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

/// Every variant, paired with the value that appears on the wire.
const KNOWN: [(Icmpv6Type, u8); 11] = [
    (Icmpv6Type::DestinationUnreachable, 1),
    (Icmpv6Type::PacketTooBig, 2),
    (Icmpv6Type::TimeExceeded, 3),
    (Icmpv6Type::ParameterProblem, 4),
    (Icmpv6Type::EchoRequest, 128),
    (Icmpv6Type::EchoReply, 129),
    (Icmpv6Type::RouterSolicitation, 133),
    (Icmpv6Type::RouterAdvertisement, 134),
    (Icmpv6Type::NeighborSolicitation, 135),
    (Icmpv6Type::NeighborAdvertisement, 136),
    (Icmpv6Type::Redirect, 137),
];

fn target_address() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
}

fn destination_address() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)
}

/// Builds a message with the given type, code 0 and checksum 0xabcd.
fn message(icmp_type: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![icmp_type, 0x00, 0xab, 0xcd];
    message.extend_from_slice(body);
    message
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn parses_the_common_header() {
    let message = message(128, REST_OF_HEADER);
    let (remaining, header) = icmpv6_header(&message).unwrap();

    assert_eq!(header.icmp_type, Icmpv6Type::EchoRequest);
    assert_eq!(header.code, 0);
    assert_eq!(header.checksum, 0xabcd);
    assert_eq!(remaining.len(), message.len() - HEADER_LEN);
}

#[test]
fn type_numbers_are_icmpv6_not_icmpv4() {
    assert_eq!(
        Icmpv6Type::try_from(1),
        Ok(Icmpv6Type::DestinationUnreachable)
    );
    assert_eq!(Icmpv6Type::try_from(3), Ok(Icmpv6Type::TimeExceeded));
    assert_eq!(Icmpv6Type::try_from(4), Ok(Icmpv6Type::ParameterProblem));
    assert_eq!(Icmpv6Type::try_from(128), Ok(Icmpv6Type::EchoRequest));
    assert_eq!(Icmpv6Type::try_from(129), Ok(Icmpv6Type::EchoReply));
    assert_eq!(Icmpv6Type::try_from(137), Ok(Icmpv6Type::Redirect));

    // And ICMPv4's numbers must not be honoured with their v4 meanings.
    assert_eq!(Icmpv6Type::try_from(0), Err(0));
    assert_eq!(Icmpv6Type::try_from(8), Err(8));
    assert_eq!(Icmpv6Type::try_from(11), Err(11));
    assert_eq!(Icmpv6Type::try_from(12), Err(12));
}

#[test]
fn discriminants_match_the_conversion() {
    for (variant, wire) in KNOWN {
        assert_eq!(variant as u8, wire);
        assert_eq!(Icmpv6Type::try_from(wire), Ok(variant));
    }
}

#[test]
fn unmodelled_types_are_rejected() {
    for icmp_type in [130, 131, 132, 143] {
        assert!(
            icmpv6_header(&message(icmp_type, REST_OF_HEADER)).is_err(),
            "type {icmp_type} unexpectedly parsed"
        );
    }
}

#[test]
fn echo_reads_identifier_and_sequence() {
    let body = concat(&[REST_OF_HEADER, TRAILING]);

    for icmp_type in [Icmpv6Type::EchoRequest, Icmpv6Type::EchoReply] {
        let (_, parsed) = icmpv6_body(icmp_type, &body).unwrap();

        assert!(
            matches!(
                parsed,
                Icmpv6Body::Echo {
                    identifier: 0x1234,
                    sequence: 0x5678,
                    data,
                } if data == TRAILING
            ),
            "{icmp_type:?} did not read an echo body"
        );
    }
}

#[test]
fn error_types_skip_the_unused_word() {
    let body = concat(&[REST_OF_HEADER, TRAILING]);

    for icmp_type in [Icmpv6Type::DestinationUnreachable, Icmpv6Type::TimeExceeded] {
        let (_, parsed) = icmpv6_body(icmp_type, &body).unwrap();

        assert!(
            matches!(parsed, Icmpv6Body::Error { quoted } if quoted == TRAILING),
            "{icmp_type:?} did not skip the unused word"
        );
    }
}

#[test]
fn packet_too_big_reads_the_mtu() {
    let body = concat(&[REST_OF_HEADER, TRAILING]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::PacketTooBig, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::PacketTooBig {
            mtu: 0x12345678,
            quoted,
        } if quoted == TRAILING
    ));
}

#[test]
fn parameter_problem_reads_a_four_byte_pointer() {
    let body = concat(&[REST_OF_HEADER, TRAILING]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::ParameterProblem, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::ParameterProblem {
            pointer: 0x12345678,
            quoted,
        } if quoted == TRAILING
    ));
}

#[test]
fn router_solicitation_keeps_only_its_options() {
    let body = concat(&[&[0, 0, 0, 0], OPTIONS]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::RouterSolicitation, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::RouterSolicitation { options } if options == OPTIONS
    ));
}

#[test]
fn router_advertisement_reads_twelve_bytes_before_its_options() {
    let body = concat(&[
        &[0x40],
        &[0x80],
        &[0x07, 0x08],
        &[0x00, 0x00, 0x75, 0x30],
        &[0x00, 0x00, 0x03, 0xe8],
        OPTIONS,
    ]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::RouterAdvertisement, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::RouterAdvertisement {
            hop_limit: 64,
            flags: 0x80,
            router_lifetime: 1800,
            reachable_time: 30_000,
            retrans_timer: 1_000,
            options,
        } if options == OPTIONS
    ));
}

#[test]
fn neighbor_solicitation_reads_the_target_address() {
    let body = concat(&[&[0, 0, 0, 0], TARGET, OPTIONS]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::NeighborSolicitation, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::NeighborSolicitation { target, options }
            if target == target_address() && options == OPTIONS
    ));
}

#[test]
fn neighbor_advertisement_reads_flags_from_the_top_byte() {
    let body = concat(&[&[0xe0, 0, 0, 0], TARGET, OPTIONS]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::NeighborAdvertisement, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::NeighborAdvertisement {
            flags: 0xe0,
            target,
            options,
        } if target == target_address() && options == OPTIONS
    ));
}

#[test]
fn redirect_reads_two_addresses() {
    let body = concat(&[&[0, 0, 0, 0], TARGET, DESTINATION, OPTIONS]);
    let (_, parsed) = icmpv6_body(Icmpv6Type::Redirect, &body).unwrap();

    assert!(matches!(
        parsed,
        Icmpv6Body::Redirect {
            target,
            destination,
            options,
        } if target == target_address() && destination == destination_address() && options == OPTIONS
    ));
}

#[test]
fn packet_joins_the_header_to_the_body() {
    let message = message(135, &concat(&[&[0, 0, 0, 0], TARGET, OPTIONS]));
    let (_, packet) = icmpv6_packet(&message).unwrap();

    assert_eq!(packet.header.icmp_type, Icmpv6Type::NeighborSolicitation);
    assert!(matches!(
        packet.body,
        Icmpv6Body::NeighborSolicitation { target, .. } if target == target_address()
    ));
}

#[test]
fn truncated_messages_error_rather_than_panic() {
    assert!(icmpv6_header(&[128, 0, 0xab]).is_err());
    assert!(icmpv6_header(&[]).is_err());
    assert!(icmpv6_body(Icmpv6Type::EchoRequest, &[0x12, 0x34, 0x56]).is_err());
    assert!(icmpv6_body(Icmpv6Type::PacketTooBig, &[0x12, 0x34]).is_err());
    assert!(icmpv6_body(Icmpv6Type::NeighborSolicitation, &[0, 0, 0, 0]).is_err());
    assert!(
        icmpv6_body(
            Icmpv6Type::NeighborSolicitation,
            &concat(&[&[0, 0, 0, 0], &TARGET[..15]])
        )
        .is_err()
    );
}
