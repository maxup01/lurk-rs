use nom::{IResult, combinator::rest, number::complete::be_u16};

pub struct UdpPacket<'a> {
    pub header: UdpHeader,
    pub payload: &'a [u8],
}

pub fn udp_packet(input: &[u8]) -> IResult<&[u8], UdpPacket<'_>> {
    let (input, header) = udp_header(input)?;
    let (input, payload) = rest(input)?;

    let udp_packet = UdpPacket { header, payload };

    Ok((input, udp_packet))
}

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
