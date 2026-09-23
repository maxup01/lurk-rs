use thiserror::Error;

#[derive(Debug, Error)]
pub enum LurkError {
    #[error("packet capture failed: {0}")]
    Pcap(#[from] pcap::Error),

    #[error(
        "no Ethernet capture device found: tunnel and loopback interfaces carry no Ethernet header and are not supported"
    )]
    NoSuitableDevice,

    #[error("no device named '{0}'")]
    DeviceNotFound(String),

    #[error("device '{device}' has link type {link_type}, but only Ethernet is supported")]
    UnsupportedLinkType { device: String, link_type: i32 },

    #[error("terminal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LurkError>;

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
