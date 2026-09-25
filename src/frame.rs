use core::convert::TryFrom;

use crate::{
    arp::ARPHeader,
    ethernet::{EtherType, EthernetHeader, ethernet_packet},
    icmp::{IcmpPacket, icmp_packet},
    ipv4::{IPv4Header, ipv4_packet},
    tcp::{TcpPacket, tcp_packet},
    udp::{UdpPacket, udp_packet},
};
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
        EtherType::ARP => todo!(),
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
}

impl TryFrom<u8> for TransportKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(Self::Icmp),
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
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
