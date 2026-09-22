use crate::{
    display::frame_row,
    error::{LurkError, Result},
    frame::parse_frame,
};
use crossbeam_channel::{Receiver, Sender};
use pcap::{Active, Capture, Device};
use ratatui::widgets::Row;

pub enum Signal {
    Stop,
}

pub struct PacketListener {
    listener: Capture<Active>,
    tx: Sender<Row<'static>>,
}

impl PacketListener {
    pub fn init() -> Result<(Self, Receiver<Row<'static>>)> {
        let (tx, rx) = crossbeam_channel::unbounded();
        let device = Device::lookup()?.ok_or(LurkError::NoSuitableDevice)?;
        let listener = device.open()?;

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
