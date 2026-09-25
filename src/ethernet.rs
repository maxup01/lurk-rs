use nom::{
    IResult,
    bytes::complete::take,
    combinator::rest,
    error::{Error, ErrorKind},
    number::complete::be_u16,
};

#[derive(Debug)]
pub struct EthernetPacket<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

pub fn ethernet_packet(input: &[u8]) -> IResult<&[u8], EthernetPacket<'_>> {
    let (input, header) = ethernet_header(input)?;
    let (input, payload) = rest(input)?;

    Ok((input, EthernetPacket { header, payload }))
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: EtherType,
}

pub fn ethernet_header(input: &[u8]) -> IResult<&[u8], EthernetHeader> {
    let (input, dst) = take(6usize)(input)?;
    let (input, src) = take(6usize)(input)?;

    let (input, ethertype) = be_u16(input)?;
    let Ok(ethertype) = EtherType::try_from(ethertype) else {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Verify)));
    };

    Ok((
        input,
        EthernetHeader {
            dst: dst.try_into().expect("dst is 6 byte array"),
            src: src.try_into().expect("src is 6 byte array"),
            ethertype,
        },
    ))
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[repr(u16)]
pub enum EtherType {
    Ethernet = 0x0001,
    IPv4 = 0x0800,
}

impl TryFrom<u16> for EtherType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, <Self as TryFrom<u16>>::Error> {
        match value {
            0x0001 => Ok(Self::Ethernet),
            0x0800 => Ok(Self::IPv4),
            other => Err(other),
        }
    }
}

#[cfg(test)]
#[path = "ethernet_tests.rs"]
mod tests;
