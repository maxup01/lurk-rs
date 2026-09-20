use lurk_rs::listener::PacketListener;

fn main() {
    let mut listener = PacketListener::init().unwrap();

    let _ = listener.handle_packets(|_| {});
}
