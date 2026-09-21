use nom::{IResult, number::complete::be_u16};

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn udp_header(input: &[u8]) -> IResult<&[u8], UdpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;

    let udp_header = UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    };

    Ok((input, udp_header))
}
