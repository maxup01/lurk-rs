use nom::{IResult, bytes::complete::take, number::complete::be_u16};

pub struct EthernetPacket {
    header: EthernetHeader,
    payload: Vec<u8>,
}

pub fn ethernet_packet(input: &[u8]) -> IResult<&[u8], EthernetPacket> {
    let (input, header) = ethernet_header(input)?;
    let payload = input[14..].to_vec();

    Ok((input, EthernetPacket { header, payload }))
}

pub struct EthernetHeader {
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
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
