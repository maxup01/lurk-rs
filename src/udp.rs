use nom::{
    IResult,
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::be_u16,
};

/// Size of the header, which `length` counts alongside the payload.
const HEADER_LEN: u16 = 8;

pub struct UdpPacket<'a> {
    pub header: UdpHeader,
    pub payload: &'a [u8],
}

pub fn udp_packet(input: &[u8]) -> IResult<&[u8], UdpPacket<'_>> {
    let (input, header) = udp_header(input)?;

    // `length` delimits the datagram: anything past it is Ethernet padding
    // added to reach the 60-byte minimum frame size, not payload.
    let (input, payload) = take(usize::from(header.payload_len()))(input)?;

    let udp_packet = UdpPacket { header, payload };

    Ok((input, udp_packet))
}

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Size of the payload following this header, in bytes.
    ///
    /// `udp_header` rejects a `length` smaller than the header itself, so this
    /// cannot underflow on a header that parsed successfully.
    pub fn payload_len(&self) -> u16 {
        self.length - HEADER_LEN
    }
}

pub fn udp_header(input: &[u8]) -> IResult<&[u8], UdpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;

    if length < HEADER_LEN {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Verify)));
    }

    let udp_header = UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    };

    Ok((input, udp_header))
}

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;
