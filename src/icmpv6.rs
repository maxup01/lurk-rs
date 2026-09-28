use nom::{
    IResult,
    error::{Error, ErrorKind},
    number::complete::{be_u8, be_u16},
};
use std::net::Ipv6Addr;

pub struct Icmpv6Packet<'a> {
    pub header: Icmpv6Header,
    pub body: Icmpv6Body<'a>,
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
