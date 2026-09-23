use crate::{
    display::{COLUMNS, CONSTRAINTS},
    error::Result,
    listener::Signal,
};
use crossbeam_channel::{Receiver, Sender};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Row, Table, TableState},
};
use std::{collections::VecDeque, time::Duration};

/// How many rows are kept for scrollback. Older rows are discarded, so memory
/// stays flat no matter how long the capture runs.
const CAPACITY: usize = 2_000;

/// Upper bound on rows pulled from the channel per redraw, so a burst of
/// traffic cannot stall the event loop and make the UI unresponsive.
const DRAIN_LIMIT: usize = 1_024;

/// How long to wait for a key before redrawing anyway. Doubles as the frame
/// interval, since new packets need to appear without any input arriving.
const TICK: Duration = Duration::from_millis(50);

pub struct Tui {
    rows: VecDeque<Row<'static>>,
    state: TableState,
    /// Whether to keep the newest row selected as packets arrive.
    following: bool,
    received: u64,
}

impl Tui {
    pub fn new() -> Self {
        Self {
            rows: VecDeque::with_capacity(CAPACITY),
            state: TableState::default(),
            following: true,
            received: 0,
        }
    }

    pub fn run(
        mut self,
        terminal: &mut DefaultTerminal,
        rows: Receiver<Row<'static>>,
        signals: Sender<Signal>,
    ) -> Result<()> {
        loop {
            self.drain(&rows);
            terminal.draw(|frame| self.draw(frame))?;

            if !event::poll(TICK)? {
                continue;
            }

            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
                && self.handle_key(key.code)
            {
                // The capture thread checks for this between packets.
                let _ = signals.send(Signal::Stop);
                return Ok(());
            }
        }
    }

    /// Moves whatever has arrived into the scrollback, oldest dropped first.
    fn drain(&mut self, rows: &Receiver<Row<'static>>) {
        for _ in 0..DRAIN_LIMIT {
            let Ok(row) = rows.try_recv() else { break };

            self.rows.push_back(row);
            self.received += 1;

            if self.rows.len() > CAPACITY {
                self.rows.pop_front();
            }
        }

        if self.following {
            self.state.select(self.rows.len().checked_sub(1));
        }
    }

    /// Returns true when the user asked to quit.
    fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            // Scrolling away from the newest row stops the view jumping.
            KeyCode::Up | KeyCode::Char('k') => {
                self.following = false;
                self.state.select_previous();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.following = false;
                self.state.select_next();
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.following = false;
                self.state.select_first();
            }
            KeyCode::Char('G') | KeyCode::End => self.following = true,
            KeyCode::Char(' ') => self.following = !self.following,
            _ => {}
        }

        false
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let [table_area, status_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(frame.area());

        let header = Row::new(COLUMNS).style(
            Style::new()
                .fg(Color::Black)
                .bg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        );

        let table = Table::new(self.rows.iter().cloned(), CONSTRAINTS)
            .header(header)
            .row_highlight_style(Style::new().bg(Color::DarkGray))
            .highlight_symbol("> ")
            .block(Block::new());

        frame.render_stateful_widget(table, table_area, &mut self.state);
        frame.render_widget(self.status(), status_area);
    }

    fn status(&self) -> Line<'static> {
        let (mode, colour) = if self.following {
            ("following", Color::Green)
        } else {
            ("paused", Color::Yellow)
        };

        Line::from(vec![
            Span::styled(
                format!(" {} packets ", self.received),
                Style::new().fg(Color::Black).bg(Color::Gray),
            ),
            Span::styled(format!(" {mode} "), Style::new().fg(colour)),
            Span::styled(
                " q quit · ↑↓ scroll · space follow · g top · G newest",
                Style::new().fg(Color::DarkGray),
            ),
        ])
    }
}

impl Default for Tui {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tui_tests.rs"]
mod tests;
