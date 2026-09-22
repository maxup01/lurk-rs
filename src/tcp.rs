use nom::{
    IResult,
    bytes::complete::take,
    combinator::rest,
    error::{Error, ErrorKind},
    number::complete::{be_u16, be_u32},
};

pub struct TcpPacket<'a> {
    pub header: TcpHeader<'a>,
    pub payload: &'a [u8],
}

pub fn tcp_packet(input: &[u8]) -> IResult<&[u8], TcpPacket<'_>> {
    let (input, header) = tcp_header(input)?;
    let (input, payload) = rest(input)?;

    let tcp_packet = TcpPacket { header, payload };

    Ok((input, tcp_packet))
}

/// Size of the fixed portion of the header, before any options.
const FIXED_HEADER_LEN: u8 = 20;

#[derive(Debug)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: &'a [u8],
}

impl TcpHeader<'_> {
    /// Total header size in bytes, including options.
    pub fn len(&self) -> u8 {
        self.data_offset * 4
    }
}

pub fn tcp_header(input: &[u8]) -> IResult<&[u8], TcpHeader<'_>> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, acknowledgment_number) = be_u32(input)?;

    let (input, offset_reserved_flags) = be_u16(input)?;

    let data_offset = (offset_reserved_flags >> 12) as u8;
    let reserved = ((offset_reserved_flags >> 9) & 0b0000000000000111) as u8;
    let flags = offset_reserved_flags & 0b0000000111111111;

    let (input, window_size) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, urgent_ptr) = be_u16(input)?;

    // Data offset counts 32-bit words and must cover at least the fixed
    // header, so anything under 5 is malformed and would underflow below.
    if data_offset < FIXED_HEADER_LEN / 4 {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Verify)));
    }

    let (input, options) = take(usize::from(data_offset * 4 - FIXED_HEADER_LEN))(input)?;

    Ok((
        input,
        TcpHeader {
            src_port,
            dst_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_ptr,
            options,
        },
    ))
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
