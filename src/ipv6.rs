pub struct IPv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_address: [u8; 16],
    pub dst_address: [u8; 16],
}
