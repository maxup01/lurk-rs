use thiserror::Error;

#[derive(Debug, Error)]
pub enum LurkError {
    #[error("packet capture failed: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("no suitable device found for packet capture")]
    NoSuitableDevice,
}

pub type Result<T> = std::result::Result<T, LurkError>;
