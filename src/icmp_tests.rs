use super::*;

const HEADER_LEN: usize = 4;

/// The four bytes at offset 4..8 — the part of the header whose meaning
/// depends on the type. Deliberately shared across the tests below so the
/// same bytes can be shown to parse four different ways.
const REST_OF_HEADER: &[u8] = &[0x12, 0x34, 0x56, 0x78];

/// Whatever follows offset 8: echo data, or a quoted packet.
const TRAILING: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

/// Builds a message with the given type, code 0 and checksum 0xabcd.
fn message(icmp_type: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![icmp_type, 0x00, 0xab, 0xcd];
    message.extend_from_slice(body);
    message
}

/// A message whose body is the shared bytes above, eight in total.
fn message_of(icmp_type: u8) -> Vec<u8> {
    let mut body = REST_OF_HEADER.to_vec();
    body.extend_from_slice(TRAILING);
    message(icmp_type, &body[..])
}

#[test]
fn parses_the_common_header() {
    let message = message_of(8);
    let (remaining, header) = icmp_header(&message).unwrap();

    assert_eq!(header.icmp_type, 8);
    assert_eq!(header.code, 0);
    assert_eq!(header.checksum, 0xabcd);
    assert_eq!(remaining.len(), message.len() - HEADER_LEN);
}

#[test]
fn echo_request_reads_identifier_and_sequence() {
    let message = message_of(8);
    let (_, body) = icmp_body(8, &message[HEADER_LEN..]).unwrap();

    assert!(matches!(
        body,
        IcmpBody::Echo {
            identifier: 0x1234,
            sequence: 0x5678,
            data,
        } if data == TRAILING
    ));
}

#[test]
fn echo_reply_shares_the_request_layout() {
    let message = message_of(0);
    let (_, body) = icmp_body(0, &message[HEADER_LEN..]).unwrap();

    assert!(matches!(
        body,
        IcmpBody::Echo {
            identifier: 0x1234,
            sequence: 0x5678,
            ..
        }
    ));
}

#[test]
fn error_types_skip_the_unused_word_before_the_quoted_packet() {
    for icmp_type in [3, 11, 12] {
        let message = message_of(icmp_type);
        let (_, body) = icmp_body(icmp_type, &message[HEADER_LEN..]).unwrap();

        assert!(
            matches!(body, IcmpBody::Error { quoted } if quoted == TRAILING),
            "type {icmp_type} did not skip the unused word"
        );
    }
}

#[test]
fn redirect_reads_the_gateway_address() {
    let message = message_of(5);
    let (_, body) = icmp_body(5, &message[HEADER_LEN..]).unwrap();

    assert!(matches!(
        body,
        IcmpBody::Redirect { gateway } if gateway == Ipv4Addr::new(18, 52, 86, 120)
    ));
}

#[test]
fn unknown_types_keep_every_byte_after_the_common_header() {
    let message = message_of(37);
    let (_, body) = icmp_body(37, &message[HEADER_LEN..]).unwrap();

    assert!(matches!(body, IcmpBody::Other(raw) if raw == &message[HEADER_LEN..]));
}

#[test]
fn packet_routes_on_type_rather_than_code() {
    let mut message = message_of(8);
    message[1] = 3;

    let (_, packet) = icmp_packet(&message).unwrap();

    assert_eq!(packet.header.code, 3);
    assert!(matches!(
        packet.body,
        IcmpBody::Echo {
            identifier: 0x1234,
            ..
        }
    ));
}

#[test]
fn known_types_convert_and_unknown_ones_report_the_raw_value() {
    assert_eq!(IcmpType::try_from(0), Ok(IcmpType::EchoReply));
    assert_eq!(IcmpType::try_from(8), Ok(IcmpType::EchoRequest));
    assert_eq!(IcmpType::try_from(11), Ok(IcmpType::TimeExceeded));

    assert_eq!(IcmpType::try_from(37), Err(37));
    assert_eq!(IcmpType::try_from(255), Err(255));
}

#[test]
fn truncated_messages_error_rather_than_panic() {
    assert!(icmp_header(&[0x08, 0x00, 0xab]).is_err());
    assert!(icmp_header(&[]).is_err());

    // An echo needs four bytes for identifier and sequence.
    assert!(icmp_body(8, &[0x12, 0x34, 0x56]).is_err());

    // An error type needs four bytes of padding before the quoted packet.
    assert!(icmp_body(3, &[0x00, 0x00, 0x00]).is_err());

    // A redirect needs four bytes of gateway address.
    assert!(icmp_body(5, &[0x12, 0x34]).is_err());
}

#[test]
fn unknown_types_tolerate_an_empty_body() {
    let (_, body) = icmp_body(37, &[]).unwrap();

    assert!(matches!(body, IcmpBody::Other(raw) if raw.is_empty()));
}
