use crate::{
    frame::{Frame, Network, Transport},
    icmp::{IcmpBody, IcmpPacket},
    tcp::TcpPacket,
};
use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Row},
};

/// Column titles, in the order `frame_row` emits its cells.
pub const COLUMNS: [&str; 4] = ["Source", "Destination", "Proto", "Info"];

/// Widths for the table. Info takes whatever is left, since it is the column
/// that benefits from extra room.
pub const CONSTRAINTS: [Constraint; 4] = [
    Constraint::Length(21),
    Constraint::Length(21),
    Constraint::Length(5),
    Constraint::Min(20),
];

/// TCP flags, most significant bit first so the order is stable. The colours
/// pick out connection lifecycle events — SYN, FIN, RST — and leave the
/// flags present on nearly every segment muted.
const TCP_FLAGS: [(u16, &str, Color); 9] = [
    (0x100, "NS", Color::DarkGray),
    (0x080, "CWR", Color::DarkGray),
    (0x040, "ECE", Color::DarkGray),
    (0x020, "URG", Color::Red),
    (0x010, "ACK", Color::DarkGray),
    (0x008, "PSH", Color::Cyan),
    (0x004, "RST", Color::Red),
    (0x002, "SYN", Color::Green),
    (0x001, "FIN", Color::Yellow),
];

const ACK: u16 = 0x010;

/// Renders one captured frame as a table row.
///
/// The row owns its text, so it outlives the borrow the `Frame` holds on the
/// capture buffer and can be kept in the UI's scrollback.
pub fn frame_row(frame: &Frame<'_>) -> Row<'static> {
    let (source, destination, protocol, info) = match &frame.network {
        Network::Ethernet { header, payload } => (
            mac(&header.src),
            mac(&header.dst),
            ethertype_span(header.ethertype as u16),
            Line::from(Span::styled(format!("{} bytes", payload.len()), dim())),
        ),
        Network::Ipv4 { header, transport } => (
            endpoint(header.src, source_port(transport)),
            endpoint(header.dst, destination_port(transport)),
            protocol_span(transport),
            transport_info(transport),
        ),
        Network::Unsupported { ethertype, payload } => (
            mac(&frame.ethernet.src),
            mac(&frame.ethernet.dst),
            ethertype_span(*ethertype),
            Line::from(Span::styled(format!("{} bytes", payload.len()), dim())),
        ),
        Network::ARP { header } => todo!(),
    };

    Row::new(vec![
        Cell::from(source),
        Cell::from(destination),
        Cell::from(protocol),
        Cell::from(info),
    ])
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

fn endpoint(address: std::net::Ipv4Addr, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{address}:{port}"),
        None => address.to_string(),
    }
}

fn mac(address: &[u8; 6]) -> String {
    address
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn source_port(transport: &Transport<'_>) -> Option<u16> {
    match transport {
        Transport::Tcp(packet) => Some(packet.header.src_port),
        Transport::Udp(packet) => Some(packet.header.src_port),
        Transport::Icmp(_) | Transport::Unsupported { .. } => None,
    }
}

fn destination_port(transport: &Transport<'_>) -> Option<u16> {
    match transport {
        Transport::Tcp(packet) => Some(packet.header.dst_port),
        Transport::Udp(packet) => Some(packet.header.dst_port),
        Transport::Icmp(_) | Transport::Unsupported { .. } => None,
    }
}

fn protocol_span(transport: &Transport<'_>) -> Span<'static> {
    let (name, colour) = match transport {
        Transport::Tcp(_) => ("TCP".to_string(), Color::Blue),
        Transport::Udp(_) => ("UDP".to_string(), Color::Cyan),
        Transport::Icmp(_) => ("ICMP".to_string(), Color::Magenta),
        Transport::Unsupported { protocol, .. } => (format!("ip{protocol}"), Color::DarkGray),
    };

    Span::styled(name, Style::new().fg(colour).add_modifier(Modifier::BOLD))
}

fn ethertype_span(ethertype: u16) -> Span<'static> {
    let (name, colour) = match ethertype {
        0x0806 => ("ARP".to_string(), Color::Yellow),
        0x86dd => ("IPv6".to_string(), Color::Green),
        0x8100 => ("VLAN".to_string(), Color::DarkGray),
        other => (format!("{other:#06x}"), Color::DarkGray),
    };

    Span::styled(name, Style::new().fg(colour).add_modifier(Modifier::BOLD))
}

fn transport_info(transport: &Transport<'_>) -> Line<'static> {
    match transport {
        Transport::Tcp(packet) => tcp_info(packet),
        Transport::Udp(packet) => {
            Line::from(Span::styled(format!("len={}", packet.payload.len()), dim()))
        }
        Transport::Icmp(packet) => icmp_info(packet),
        Transport::Unsupported { payload, .. } => {
            Line::from(Span::styled(format!("{} bytes", payload.len()), dim()))
        }
    }
}

fn tcp_info(packet: &TcpPacket<'_>) -> Line<'static> {
    let header = &packet.header;
    let mut spans = flag_spans(header.flags);

    spans.push(Span::styled(
        format!(" seq={}", header.sequence_number),
        dim(),
    ));

    // An acknowledgment number only means anything once ACK is set.
    if header.flags & ACK != 0 {
        spans.push(Span::styled(
            format!(" ack={}", header.acknowledgment_number),
            dim(),
        ));
    }

    spans.push(Span::styled(
        format!(" win={} len={}", header.window_size, packet.payload.len()),
        dim(),
    ));

    Line::from(spans)
}

fn flag_spans(flags: u16) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled("[", dim())];
    let mut first = true;

    for (bit, name, colour) in TCP_FLAGS {
        if flags & bit == 0 {
            continue;
        }

        if !first {
            spans.push(Span::raw(" "));
        }
        first = false;

        spans.push(Span::styled(name, Style::new().fg(colour)));
    }

    if first {
        spans.push(Span::styled("none", dim()));
    }

    spans.push(Span::styled("]", dim()));
    spans
}

fn icmp_info(packet: &IcmpPacket<'_>) -> Line<'static> {
    let icmp_type = packet.header.icmp_type;
    let name = Span::styled(icmp_name(icmp_type), Style::new().fg(Color::Magenta));

    match &packet.body {
        IcmpBody::Echo {
            identifier,
            sequence,
            data,
        } => Line::from(vec![
            name,
            Span::styled(
                format!(" id={identifier} seq={sequence} len={}", data.len()),
                dim(),
            ),
        ]),
        IcmpBody::Error { quoted } => {
            let mut spans = vec![Span::styled(
                icmp_name(icmp_type),
                Style::new().fg(Color::Red),
            )];

            if let Some(reason) = unreachable_reason(icmp_type, packet.header.code) {
                spans.push(Span::styled(
                    format!(" ({reason})"),
                    Style::new().fg(Color::Red),
                ));
            }

            spans.push(Span::styled(
                format!(", {} bytes quoted", quoted.len()),
                dim(),
            ));

            Line::from(spans)
        }
        IcmpBody::Redirect { gateway } => {
            Line::from(vec![name, Span::styled(format!(" via {gateway}"), dim())])
        }
        IcmpBody::Other(raw) => Line::from(Span::styled(
            format!(
                "type {icmp_type} code {} ({} bytes)",
                packet.header.code,
                raw.len()
            ),
            dim(),
        )),
    }
}

fn icmp_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "echo reply",
        3 => "destination unreachable",
        5 => "redirect",
        8 => "echo request",
        11 => "time exceeded",
        12 => "parameter problem",
        _ => "unknown",
    }
}

/// Codes worth spelling out — in practice the unreachable ones, since they
/// are why you are looking at the row in the first place.
fn unreachable_reason(icmp_type: u8, code: u8) -> Option<&'static str> {
    if icmp_type != 3 {
        return None;
    }

    match code {
        0 => Some("net unreachable"),
        1 => Some("host unreachable"),
        2 => Some("protocol unreachable"),
        3 => Some("port unreachable"),
        4 => Some("fragmentation needed"),
        _ => None,
    }
}
