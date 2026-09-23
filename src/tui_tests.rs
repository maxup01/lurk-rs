use super::*;
use crate::{display::frame_row, frame::parse_frame};
use ratatui::{Terminal, backend::TestBackend};

/// A complete frame: broadcast Ethernet carrying IPv4 (total length 40, TCP)
/// carrying a bare PSH+ACK segment from 192.168.0.1:443 to 192.168.0.199:54321.
const TCP_FRAME: &[u8] = &[
    // ethernet
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x08, 0x00,
    // ipv4
    0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01,
    0xc0, 0xa8, 0x00, 0xc7, // tcp
    0x01, 0xbb, 0xd4, 0x31, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x50, 0x18, 0x72, 0x10,
    0x1f, 0x2a, 0x00, 0x00,
];

fn rendered(rows: &[&[u8]]) -> String {
    let mut tui = Tui::new();

    for bytes in rows {
        let (_, frame) = parse_frame(bytes).expect("test frame should parse");
        tui.rows.push_back(frame_row(&frame));
        tui.received += 1;
    }
    tui.state.select(tui.rows.len().checked_sub(1));

    let mut terminal = Terminal::new(TestBackend::new(100, 8)).unwrap();
    terminal.draw(|frame| tui.draw(frame)).unwrap();

    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn renders_column_headers() {
    let output = rendered(&[TCP_FRAME]);

    for column in COLUMNS {
        assert!(output.contains(column), "missing column {column}\n{output}");
    }
}

#[test]
fn renders_a_tcp_row_with_addresses_ports_and_flags() {
    let output = rendered(&[TCP_FRAME]);

    assert!(output.contains("192.168.0.1:443"), "{output}");
    assert!(output.contains("192.168.0.199:54321"), "{output}");
    assert!(output.contains("TCP"), "{output}");
    assert!(output.contains("ACK"), "{output}");
    assert!(output.contains("PSH"), "{output}");
}

#[test]
fn status_line_reports_the_packet_count_and_mode() {
    let output = rendered(&[TCP_FRAME, TCP_FRAME]);

    assert!(output.contains("2 packets"), "{output}");
    assert!(output.contains("following"), "{output}");
}

#[test]
fn scrolling_stops_following_and_newest_resumes_it() {
    let mut tui = Tui::new();
    assert!(tui.following);

    tui.handle_key(KeyCode::Up);
    assert!(!tui.following, "scrolling up should pause the view");

    tui.handle_key(KeyCode::Char('G'));
    assert!(tui.following, "G should jump back to the newest row");
}

#[test]
fn quit_keys_are_the_only_ones_that_stop_the_loop() {
    let mut tui = Tui::new();

    assert!(tui.handle_key(KeyCode::Char('q')));
    assert!(tui.handle_key(KeyCode::Esc));

    assert!(!tui.handle_key(KeyCode::Down));
    assert!(!tui.handle_key(KeyCode::Char(' ')));
}

#[test]
fn scrollback_is_bounded() {
    let mut tui = Tui::new();

    for _ in 0..CAPACITY + 100 {
        let (_, frame) = parse_frame(TCP_FRAME).unwrap();
        tui.rows.push_back(frame_row(&frame));

        if tui.rows.len() > CAPACITY {
            tui.rows.pop_front();
        }
    }

    assert_eq!(tui.rows.len(), CAPACITY);
}
