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
