use nom::{
    IResult,
    number::complete::{be_u8, be_u16},
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
