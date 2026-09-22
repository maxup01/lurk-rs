use crossbeam_channel::bounded;
use lurk_rs::listener::PacketListener;

fn main() {
    let (mut listener, row_rx) = PacketListener::init().unwrap();

    let (_tx, rx) = bounded(5);

    let _ = listener.handle_packets(rx);
}
