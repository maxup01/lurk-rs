use std::net::Ipv4Addr;

pub struct IPv4Header<'a> {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    options: &'a [u8],
}
