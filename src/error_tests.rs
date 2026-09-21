use super::*;
use std::error::Error as StdError;

#[test]
fn wraps_pcap_error() {
    let err = LurkError::from(pcap::Error::TimeoutExpired);

    assert!(matches!(err, LurkError::Pcap(pcap::Error::TimeoutExpired)));
}

#[test]
fn question_mark_converts_pcap_errors() {
    fn fails() -> Result<()> {
        Err(pcap::Error::InsufficientMemory)?
    }

    assert!(matches!(
        fails(),
        Err(LurkError::Pcap(pcap::Error::InsufficientMemory))
    ));
}

#[test]
fn pcap_display_keeps_the_underlying_message() {
    let err = LurkError::from(pcap::Error::PcapError("device busy".into()));

    let message = err.to_string();
    assert!(message.contains("packet capture failed"), "{message}");
    assert!(message.contains("device busy"), "{message}");
}

#[test]
fn no_suitable_device_displays_its_own_message() {
    assert_eq!(
        LurkError::NoSuitableDevice.to_string(),
        "no suitable device found for packet capture"
    );
}

#[test]
fn only_the_wrapping_variant_reports_a_source() {
    let wrapped = LurkError::from(pcap::Error::TimeoutExpired);
    assert!(wrapped.source().is_some());

    assert!(LurkError::NoSuitableDevice.source().is_none());
}
