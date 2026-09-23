use pcap::{Capture, Device};

fn main() {
    for name in ["en0", "utun0", "lo0"] {
        let Some(device) = Device::list().unwrap().into_iter().find(|d| d.name == name) else {
            continue;
        };
        match Capture::from_device(device).unwrap().immediate_mode(true).open() {
            Ok(cap) => println!("{name:<8} datalink = {:?}", cap.get_datalink()),
            Err(e) => println!("{name:<8} open failed: {e}"),
        }
    }
}
