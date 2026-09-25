use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32},
};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub sha: [u8; 6],
    pub spa: Ipv4Addr,
    pub tha: [u8; 6],
    pub tpa: Ipv4Addr,
}

pub fn arp_packet(input: &[u8]) -> IResult<&[u8], ArpPacket> {
    let (input, htype) = be_u16(input)?;
    let (input, ptype) = be_u16(input)?;
    let (input, hlen) = be_u8(input)?;
    let (input, plen) = be_u8(input)?;
    let (input, oper) = be_u16(input)?;
    let (input, sha) = take(6usize)(input)?;
    let (input, spa) = be_u32(input)?;
    let (input, tha) = take(6usize)(input)?;
    let (input, tpa) = be_u32(input)?;

    Ok((
        input,
        ArpPacket {
            htype,
            ptype,
            hlen,
            plen,
            oper,
            sha: sha.try_into().expect("sha is 6 byte array"),
            spa: Ipv4Addr::from(spa),
            tha: tha.try_into().expect("tha is 6 byte array"),
            tpa: Ipv4Addr::from(tpa),
        },
    ))
}
