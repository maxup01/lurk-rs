use std::net::Ipv4Addr;

pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

pub enum IcmpBody<'a> {
    Echo {
        identifier: u16,
        sequence: u16,
        data: &'a [u8],
    },
    Error {
        quoted: &'a [u8],
    },
    Redirect {
        gateway: Ipv4Addr,
    },
    Other(&'a [u8]),
}
