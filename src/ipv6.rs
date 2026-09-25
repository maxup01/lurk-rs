pub struct IPv6Header {
    /// Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits).
    pub vtf: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: [u8; 16],
    pub dst_address: [u8; 16],
}

pub struct IPv6Packet<'a> {
    pub header: IPv6Header,
    pub payload: &'a [u8],
}
