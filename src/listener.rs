use crate::error::{LurkError, Result};
use pcap::{Active, Capture, Device};

pub struct PacketListener {
    listener: Capture<Active>,
}

impl PacketListener {
    pub fn init() -> Result<Self> {
        let device = Device::lookup()?.ok_or(LurkError::NoSuitableDevice)?;
        let listener = device.open()?;

        Ok(Self { listener })
    }
}
