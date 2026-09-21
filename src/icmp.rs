use nom::{
    IResult,
    bytes::complete::take,
    combinator::rest,
    number::complete::{be_u8, be_u16, be_u32},
};
use std::net::Ipv4Addr;

pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

pub fn icmp_header(input: &[u8]) -> IResult<&[u8], IcmpHeader> {
    let (input, icmp_type) = be_u8(input)?;
    let (input, code) = be_u8(input)?;
    let (input, checksum) = be_u16(input)?;

    let header = IcmpHeader {
        icmp_type,
        code,
        checksum,
    };

    Ok((input, header))
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
}

impl TryFrom<u8> for IcmpType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0 => Ok(Self::EchoReply),
            3 => Ok(Self::DestinationUnreachable),
            5 => Ok(Self::Redirect),
            8 => Ok(Self::EchoRequest),
            11 => Ok(Self::TimeExceeded),
            12 => Ok(Self::ParameterProblem),
            other => Err(other),
        }
    }
}

pub enum IcmpBody<'a> {
    Echo {
        identifier: u16,
        sequence: u16,
        data: &'a [u8],
    },
    Error {
        quoted: &'a [u8],
    },
    Redirect {
        gateway: Ipv4Addr,
    },
    Other(&'a [u8]),
}
