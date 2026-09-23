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
fn no_suitable_device_explains_why_nothing_was_opened() {
    let message = LurkError::NoSuitableDevice.to_string();

    assert!(message.contains("Ethernet"), "{message}");
    assert!(message.contains("tunnel"), "{message}");
}

#[test]
fn device_errors_name_the_device() {
    let missing = LurkError::DeviceNotFound("en9".to_string()).to_string();
    assert!(missing.contains("en9"), "{missing}");

    let wrong_link = LurkError::UnsupportedLinkType {
        device: "utun0".to_string(),
        link_type: 0,
    }
    .to_string();
    assert!(wrong_link.contains("utun0"), "{wrong_link}");
    assert!(wrong_link.contains('0'), "{wrong_link}");
}

#[test]
fn only_the_wrapping_variant_reports_a_source() {
    let wrapped = LurkError::from(pcap::Error::TimeoutExpired);
    assert!(wrapped.source().is_some());

    assert!(LurkError::NoSuitableDevice.source().is_none());
}
