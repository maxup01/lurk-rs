use nom::{
    IResult,
    bytes::complete::take,
    combinator::rest,
    error::{Error, ErrorKind},
    number::complete::{be_u8, be_u16, be_u32},
};
use std::net::Ipv6Addr;

pub struct Icmpv6Packet<'a> {
    pub header: Icmpv6Header,
    pub body: Icmpv6Body<'a>,
}

pub fn icmpv6_packet(input: &[u8]) -> IResult<&[u8], Icmpv6Packet<'_>> {
    let (input, header) = icmpv6_header(input)?;
    let (input, body) = icmpv6_body(header.icmp_type, input)?;

    let packet = Icmpv6Packet { header, body };

    Ok((input, packet))
}

pub struct Icmpv6Header {
    pub icmp_type: Icmpv6Type,
    pub code: u8,
    pub checksum: u16,
}

pub fn icmpv6_header(input: &[u8]) -> IResult<&[u8], Icmpv6Header> {
    let (input, icmp_type) = be_u8(input)?;
    let (input, code) = be_u8(input)?;
    let (input, checksum) = be_u16(input)?;

    let Ok(icmp_type) = Icmpv6Type::try_from(icmp_type) else {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Verify)));
    };

    let header = Icmpv6Header {
        icmp_type,
        code,
        checksum,
    };

    Ok((input, header))
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    // Errors: 0..=127
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    // Informational: 128..=255
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl TryFrom<u8> for Icmpv6Type {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(Self::DestinationUnreachable),
            2 => Ok(Self::PacketTooBig),
            3 => Ok(Self::TimeExceeded),
            4 => Ok(Self::ParameterProblem),
            128 => Ok(Self::EchoRequest),
            129 => Ok(Self::EchoReply),
            133 => Ok(Self::RouterSolicitation),
            134 => Ok(Self::RouterAdvertisement),
            135 => Ok(Self::NeighborSolicitation),
            136 => Ok(Self::NeighborAdvertisement),
            137 => Ok(Self::Redirect),
            other => Err(other),
        }
    }
}

pub enum Icmpv6Body<'a> {
    Echo {
        identifier: u16,
        sequence: u16,
        data: &'a [u8],
    },
    Error {
        quoted: &'a [u8],
    },
    PacketTooBig {
        mtu: u32,
        quoted: &'a [u8],
    },
    ParameterProblem {
        pointer: u32,
        quoted: &'a [u8],
    },
    RouterSolicitation {
        options: &'a [u8],
    },
    RouterAdvertisement {
        hop_limit: u8,
        flags: u8,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: &'a [u8],
    },
    NeighborSolicitation {
        target: Ipv6Addr,
        options: &'a [u8],
    },
    NeighborAdvertisement {
        flags: u8,
        target: Ipv6Addr,
        options: &'a [u8],
    },
    Redirect {
        target: Ipv6Addr,
        destination: Ipv6Addr,
        options: &'a [u8],
    },
    Other(&'a [u8]),
}

pub fn icmpv6_body(icmp_type: Icmpv6Type, input: &[u8]) -> IResult<&[u8], Icmpv6Body<'_>> {
    match icmp_type {
        Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply => {
            let (input, identifier) = be_u16(input)?;
            let (input, sequence) = be_u16(input)?;
            let (input, data) = rest(input)?;

            Ok((
                input,
                Icmpv6Body::Echo {
                    identifier,
                    sequence,
                    data,
                },
            ))
        }
        Icmpv6Type::DestinationUnreachable | Icmpv6Type::TimeExceeded => {
            let (input, _unused) = take(4usize)(input)?;
            let (input, quoted) = rest(input)?;

            Ok((input, Icmpv6Body::Error { quoted }))
        }
        Icmpv6Type::PacketTooBig => {
            let (input, mtu) = be_u32(input)?;
            let (input, quoted) = rest(input)?;

            Ok((input, Icmpv6Body::PacketTooBig { mtu, quoted }))
        }
        Icmpv6Type::ParameterProblem => {
            let (input, pointer) = be_u32(input)?;
            let (input, quoted) = rest(input)?;

            Ok((input, Icmpv6Body::ParameterProblem { pointer, quoted }))
        }
        Icmpv6Type::RouterSolicitation => {
            let (input, _reserved) = take(4usize)(input)?;
            let (input, options) = rest(input)?;

            Ok((input, Icmpv6Body::RouterSolicitation { options }))
        }
        Icmpv6Type::RouterAdvertisement => {
            let (input, hop_limit) = be_u8(input)?;
            let (input, flags) = be_u8(input)?;
            let (input, router_lifetime) = be_u16(input)?;
            let (input, reachable_time) = be_u32(input)?;
            let (input, retrans_timer) = be_u32(input)?;
            let (input, options) = rest(input)?;

            Ok((
                input,
                Icmpv6Body::RouterAdvertisement {
                    hop_limit,
                    flags,
                    router_lifetime,
                    reachable_time,
                    retrans_timer,
                    options,
                },
            ))
        }
        Icmpv6Type::NeighborSolicitation => {
            let (input, _reserved) = take(4usize)(input)?;
            let (input, target) = ipv6_address(input)?;
            let (input, options) = rest(input)?;

            Ok((input, Icmpv6Body::NeighborSolicitation { target, options }))
        }
        Icmpv6Type::NeighborAdvertisement => {
            let (input, flags) = be_u8(input)?;
            let (input, _reserved) = take(3usize)(input)?;
            let (input, target) = ipv6_address(input)?;
            let (input, options) = rest(input)?;

            Ok((
                input,
                Icmpv6Body::NeighborAdvertisement {
                    flags,
                    target,
                    options,
                },
            ))
        }
        Icmpv6Type::Redirect => {
            let (input, _reserved) = take(4usize)(input)?;
            let (input, target) = ipv6_address(input)?;
            let (input, destination) = ipv6_address(input)?;
            let (input, options) = rest(input)?;

            Ok((
                input,
                Icmpv6Body::Redirect {
                    target,
                    destination,
                    options,
                },
            ))
        }
    }
}

fn ipv6_address(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (input, address) = take(16usize)(input)?;

    Ok((
        input,
        Ipv6Addr::from(<[u8; 16]>::try_from(address).expect("address is 16 byte array")),
    ))
}

#[cfg(test)]
#[path = "icmpv6_tests.rs"]
mod tests;
