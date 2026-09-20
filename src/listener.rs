use crate::error::{LurkError, Result};
use pcap::{Active, Capture, Device, Packet};

pub struct PacketListener {
    listener: Capture<Active>,
}

impl PacketListener {
    pub fn init() -> Result<Self> {
        let device = Device::lookup()?.ok_or(LurkError::NoSuitableDevice)?;
        let listener = device.open()?;

        Ok(Self { listener })
    }

    pub fn handle_packets<F: Fn(Packet<'_>)>(&mut self, packet_handler: F) -> Result<()> {
        loop {
            match self.listener.next_packet() {
                Ok(packet) => packet_handler(packet),
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}
