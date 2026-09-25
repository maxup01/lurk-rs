use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32},
};

pub struct IPv6Header {
    /// Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits).
    pub vtf: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: [u8; 16],
    pub dst_address: [u8; 16],
}

pub fn ipv6_header(input: &[u8]) -> IResult<&[u8], IPv6Header> {
    let (input, vtf) = be_u32(input)?;
    let (input, payload_length) = be_u16(input)?;
    let (input, next_header) = be_u8(input)?;
    let (input, hop_limit) = be_u8(input)?;
    let (input, src_address) = take(16usize)(input)?;
    let (input, dst_address) = take(16usize)(input)?;

    Ok((
        input,
        IPv6Header {
            vtf,
            payload_length,
            next_header,
            hop_limit,
            src_address: src_address
                .try_into()
                .expect("src_address is 16 bytes long"),
            dst_address: dst_address
                .try_into()
                .expect("dst_address is 16 bytes long"),
        },
    ))
}

pub struct IPv6Packet<'a> {
    pub header: IPv6Header,
    pub payload: &'a [u8],
}
