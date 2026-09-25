use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32},
};
use std::net::Ipv6Addr;

pub struct IPv6Header {
    /// Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits).
    pub vtf: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: Ipv6Addr,
    pub dst_address: Ipv6Addr,
}

pub struct IPv6Packet<'a> {
    pub header: IPv6Header,
    /// The transport protocol the extension header chain resolves to, using
    /// the same numbering as IPv4's `protocol` field.
    pub protocol: u8,
    pub payload: &'a [u8],
}

// Extension header types that can appear in the `next_header` chain before
// reaching a transport protocol.
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DESTINATION_OPTIONS: u8 = 60;

pub fn ipv6_header(input: &[u8]) -> IResult<&[u8], IPv6Header> {
    let (input, vtf) = be_u32(input)?;
    let (input, payload_length) = be_u16(input)?;
    let (input, next_header) = be_u8(input)?;
    let (input, hop_limit) = be_u8(input)?;
    let (input, src_address) = take(16usize)(input)?;
    let (input, dst_address) = take(16usize)(input)?;

    Ok((
        input,
        IPv6Header {
            vtf,
            payload_length,
            next_header,
            hop_limit,
            src_address: Ipv6Addr::from(
                <[u8; 16]>::try_from(src_address).expect("src_address is 16 byte array"),
            ),
            dst_address: Ipv6Addr::from(
                <[u8; 16]>::try_from(dst_address).expect("dst_address is 16 byte array"),
            ),
        },
    ))
}

pub fn ipv6_packet(input: &[u8]) -> IResult<&[u8], IPv6Packet<'_>> {
    let (input, header) = ipv6_header(input)?;
    let (input, payload) = take(header.payload_length)(input)?;

    let (payload, protocol) = skip_extension_headers(payload, header.next_header)?;

    Ok((
        input,
        IPv6Packet {
            header,
            protocol,
            payload,
        },
    ))
}

/// Walks the `next_header` chain past any extension headers, returning the
/// remaining payload and the protocol number it starts with. Each extension
/// header carries its own next-header byte, so the field doesn't necessarily
/// name a transport protocol until the chain bottoms out.
fn skip_extension_headers(mut input: &[u8], mut next_header: u8) -> IResult<&[u8], u8> {
    loop {
        match next_header {
            HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS => {
                let (rest, header) = be_u8(input)?;
                let (rest, hdr_ext_len) = be_u8(rest)?;
                let (rest, _) = take(usize::from(hdr_ext_len) * 8 + 6)(rest)?;

                next_header = header;
                input = rest;
            }
            FRAGMENT => {
                let (rest, header) = be_u8(input)?;
                let (rest, _) = take(7usize)(rest)?;

                next_header = header;
                input = rest;
            }
            other => return Ok((input, other)),
        }
    }
}
