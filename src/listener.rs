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
        while let Ok(packet) = self.listener.next_packet() {
            packet_handler(packet);
        }

        Ok(())
    }
}
