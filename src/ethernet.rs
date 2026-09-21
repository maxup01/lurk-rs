use nom::{IResult, bytes::complete::take, number::complete::be_u16};

struct EthernetHeader {
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
}

fn ethernet_header(input: &[u8]) -> IResult<&[u8], EthernetHeader> {
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
