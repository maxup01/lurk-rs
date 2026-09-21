use nom::{
    IResult,
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::{be_u8, be_u16, be_u32},
};
use std::net::Ipv4Addr;

/// Size of the fixed portion of the header, before any options.
const FIXED_HEADER_LEN: u8 = 20;

#[derive(Debug)]
pub struct IPv4Header<'a> {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    options: &'a [u8],
}

impl IPv4Header<'_> {
    /// Total header size in bytes, including options.
    pub fn len(&self) -> u8 {
        self.ihl * 4
    }

    pub fn payload_len(&self) -> u16 {
        self.total_length - self.len() as u16
    }
}

pub fn ipv4_header(input: &[u8]) -> IResult<&[u8], IPv4Header<'_>> {
    let (input, version_ihl) = be_u8(input)?;

    let version = version_ihl >> 4;
    let ihl = version_ihl & 0b00001111;

    let (input, dscp_ecn) = be_u8(input)?;

    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0b00000011;

    let (input, total_length) = be_u16(input)?;
    let (input, identification) = be_u16(input)?;

    let (input, flags_fragment_offset) = be_u16(input)?;

    let flags = (flags_fragment_offset >> 13) as u8;
    let fragment_offset = flags_fragment_offset & 0b0001111111111111;

    let (input, ttl) = be_u8(input)?;
    let (input, protocol) = be_u8(input)?;
    let (input, header_checksum) = be_u16(input)?;
    let (input, src) = be_u32(input)?;
    let (input, dst) = be_u32(input)?;

    // IHL counts 32-bit words and must cover at least the fixed header, so
    // anything under 5 is malformed and would underflow the options length.
    if ihl < FIXED_HEADER_LEN / 4 {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Verify)));
    }

    let (input, options) = take(usize::from(ihl * 4 - FIXED_HEADER_LEN))(input)?;

    Ok((
        input,
        IPv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src: Ipv4Addr::from(src),
            dst: Ipv4Addr::from(dst),
            options,
        },
    ))
}
