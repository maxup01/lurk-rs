use crate::{
    ethernet::{EthernetHeader, ethernet_packet},
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
        0x0800 => {
            let (_, ip) = ipv4_packet(eth.payload)?;
            let transport = match ip.header.protocol {
                1 => Transport::Icmp(icmp_packet(ip.payload)?.1),
                6 => Transport::Tcp(tcp_packet(ip.payload)?.1),
                17 => Transport::Udp(udp_packet(ip.payload)?.1),
                protocol => Transport::Unsupported {
                    protocol,
                    payload: ip.payload,
                },
            };
            Network::Ipv4 {
                header: ip.header,
                transport,
            }
        }
        ethertype => Network::Unsupported {
            ethertype,
            payload: eth.payload,
        },
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
