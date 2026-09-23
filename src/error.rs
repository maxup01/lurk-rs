use thiserror::Error;

#[derive(Debug, Error)]
pub enum LurkError {
    #[error("packet capture failed: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("no suitable device found for packet capture")]
    NoSuitableDevice,

    #[error("terminal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LurkError>;

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
