use crate::{icmp::IcmpPacket, tcp::TcpPacket, udp::UdpPacket};

pub enum Transport<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Unsupported { protocol: u8, payload: &'a [u8] },
}
