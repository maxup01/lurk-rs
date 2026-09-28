use crate::{
    arp::{ARPHeader, arp_packet},
    ethernet::{EtherType, EthernetHeader, ethernet_packet},
    icmp::{IcmpPacket, icmp_packet},
    icmpv6::{Icmpv6Packet, icmpv6_packet},
    ipv4::{IPv4Header, ipv4_packet},
    ipv6::{ExtensionHeaders, IPv6Header, ipv6_packet},
    tcp::{TcpPacket, tcp_packet},
    udp::{UdpPacket, udp_packet},
};
use core::convert::TryFrom;
use nom::IResult;

pub struct Frame<'a> {
    pub ethernet: EthernetHeader,
    pub network: Network<'a>,
}

pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Frame<'_>> {
    let (input, eth) = ethernet_packet(input)?;

    let network = match eth.header.ethertype {
        EtherType::Ethernet => Network::Ethernet {
            header: eth.header.clone(),
            payload: eth.payload,
        },
        EtherType::IPv4 => {
            let (_, ip) = ipv4_packet(eth.payload)?;

            let transport = match TransportKind::try_from(ip.header.protocol) {
                Ok(TransportKind::Icmp) => Transport::Icmp(icmp_packet(ip.payload)?.1),
                Ok(TransportKind::Tcp) => Transport::Tcp(tcp_packet(ip.payload)?.1),
                Ok(TransportKind::Udp) => Transport::Udp(udp_packet(ip.payload)?.1),
                Ok(TransportKind::Icmpv6) => Transport::Icmpv6(icmpv6_packet(ip.payload)?.1),
                Err(protocol) => Transport::Unsupported {
                    protocol,
                    payload: ip.payload,
                },
            };

            Network::Ipv4 {
                header: ip.header,
                transport,
            }
        }
        EtherType::ARP => {
            let (_, arp) = arp_packet(eth.payload)?;

            Network::ARP { header: arp }
        }
        EtherType::IPv6 => {
            let (_, ip) = ipv6_packet(eth.payload)?;

            let transport = match TransportKind::try_from(ip.protocol) {
                Ok(TransportKind::Icmp) => Transport::Icmp(icmp_packet(ip.payload)?.1),
                Ok(TransportKind::Tcp) => Transport::Tcp(tcp_packet(ip.payload)?.1),
                Ok(TransportKind::Udp) => Transport::Udp(udp_packet(ip.payload)?.1),
                Ok(TransportKind::Icmpv6) => Transport::Icmpv6(icmpv6_packet(ip.payload)?.1),
                Err(protocol) => Transport::Unsupported {
                    protocol,
                    payload: ip.payload,
                },
            };

            Network::Ipv6 {
                header: ip.header,
                extensions: ip.extensions,
                transport,
            }
        }
    };

    Ok((
        input,
        Frame {
            ethernet: eth.header,
            network,
        },
    ))
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

impl TryFrom<u8> for TransportKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(Self::Icmp),
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
            58 => Ok(Self::Icmpv6),
            other => Err(other),
        }
    }
}

pub enum Network<'a> {
    Ethernet {
        header: EthernetHeader,
        payload: &'a [u8],
    },
    Ipv4 {
        header: IPv4Header<'a>,
        transport: Transport<'a>,
    },
    ARP {
        header: ARPHeader,
    },
    Ipv6 {
        header: IPv6Header,
        extensions: ExtensionHeaders,
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
    Icmpv6(Icmpv6Packet<'a>),
    Unsupported { protocol: u8, payload: &'a [u8] },
}
