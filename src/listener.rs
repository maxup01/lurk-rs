use crate::{
    display::frame_row,
    error::{LurkError, Result},
    frame::parse_frame,
};
use crossbeam_channel::{Receiver, Sender};
use pcap::{Active, Capture, Device, Linktype};
use ratatui::widgets::Row;

const READ_TIMEOUT_MS: i32 = 100;

pub enum Signal {
    Stop,
}

pub struct PacketListener {
    listener: Capture<Active>,
    tx: Sender<Row<'static>>,
}

impl PacketListener {
    /// Opens `device` by name, or the first Ethernet interface when none is
    /// given.
    pub fn init(device: Option<&str>) -> Result<(Self, Receiver<Row<'static>>)> {
        let (tx, rx) = crossbeam_channel::unbounded();

        let listener = match device {
            Some(name) => open_named(name)?,
            None => open_first_ethernet()?,
        };

        Ok((Self { listener, tx }, rx))
    }

    pub fn handle_packets(&mut self, rx: Receiver<Signal>) -> Result<()> {
        loop {
            if let Ok(Signal::Stop) = rx.try_recv() {
                return Ok(());
            }

            match self.listener.next_packet() {
                Ok(packet) => {
                    if let Ok((_, frame)) = parse_frame(packet.data) {
                        self.tx
                            .send(frame_row(&frame))
                            .expect("failed to send frame row");
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

fn open(device: Device) -> Result<Capture<Active>> {
    let capture = Capture::from_device(device)?
        .immediate_mode(true)
        .timeout(READ_TIMEOUT_MS)
        .open()?;

    Ok(capture)
}

fn open_named(name: &str) -> Result<Capture<Active>> {
    let device = Device::list()?
        .into_iter()
        .find(|device| device.name == name)
        .ok_or_else(|| LurkError::DeviceNotFound(name.to_string()))?;

    let capture = open(device)?;
    let link_type = capture.get_datalink();

    if link_type != Linktype::ETHERNET {
        return Err(LurkError::UnsupportedLinkType {
            device: name.to_string(),
            link_type: link_type.0,
        });
    }

    Ok(capture)
}

/// Opens the first interface that actually delivers Ethernet frames.
fn open_first_ethernet() -> Result<Capture<Active>> {
    let candidates = Device::list()?.into_iter().filter(|device| {
        device.flags.is_up() && device.flags.is_running() && !device.flags.is_loopback()
    });

    for device in candidates {
        let Ok(capture) = open(device) else { continue };

        if capture.get_datalink() == Linktype::ETHERNET {
            return Ok(capture);
        }
    }

    Err(LurkError::NoSuitableDevice)
}
