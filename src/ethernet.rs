use nom::{IResult, bytes::complete::take, combinator::rest, number::complete::be_u16};

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

#[derive(Debug)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

pub fn ethernet_header(input: &[u8]) -> IResult<&[u8], EthernetHeader> {
    let (input, dst) = take(6usize)(input)?;
    let (input, src) = take(6usize)(input)?;
    let (input, ethertype) = be_u16(input)?;
    Ok((
        input,
        EthernetHeader {
            dst: dst.try_into().expect("dst is 6 byte array"),
            src: src.try_into().expect("src is 6 byte array"),
            ethertype,
        },
    ))
}

#[cfg(test)]
#[path = "ethernet_tests.rs"]
mod tests;
