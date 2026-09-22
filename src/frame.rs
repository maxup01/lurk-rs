use crate::{icmp::IcmpPacket, ipv4::IPv4Header, tcp::TcpPacket, udp::UdpPacket};

pub enum Network<'a> {
    Ipv4 {
        header: IPv4Header<'a>,
        transport: Transport<'a>,
    },
    Unsupported {
        ethertype: u16,
        payload: &'a [u8],
    },
}

pub enum Transport<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Unsupported { protocol: u8, payload: &'a [u8] },
}
