use crate::icmp::IcmpHeader;

pub type Icmpv6Header = IcmpHeader;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6Type {
    // Errors: 0..=127
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    // Informational: 128..=255
    EchoRequest = 128,
    EchoReply = 129,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl TryFrom<u8> for Icmpv6Type {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            1 => Ok(Self::DestinationUnreachable),
            2 => Ok(Self::PacketTooBig),
            3 => Ok(Self::TimeExceeded),
            4 => Ok(Self::ParameterProblem),
            128 => Ok(Self::EchoRequest),
            129 => Ok(Self::EchoReply),
            133 => Ok(Self::RouterSolicitation),
            134 => Ok(Self::RouterAdvertisement),
            135 => Ok(Self::NeighborSolicitation),
            136 => Ok(Self::NeighborAdvertisement),
            137 => Ok(Self::Redirect),
            other => Err(other),
        }
    }
}
