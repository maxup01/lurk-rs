use crossbeam_channel::bounded;
use lurk_rs::{error::Result, listener::PacketListener, tui::Tui};
use std::{process::ExitCode, thread};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lurk: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let (mut listener, rows) = PacketListener::init(Some("en0"))?;
    let (signal_tx, signal_rx) = bounded(1);

    thread::spawn(move || listener.handle_packets(signal_rx));

    let mut terminal = ratatui::init();
    let result = Tui::new().run(&mut terminal, rows, signal_tx);
    ratatui::restore();

    result
}
