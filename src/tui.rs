use crate::{dns_leak::DnsData, trace::TraceData};
use ratatui::{
    crossterm::{
        self,
        event::{Event, KeyCode},
    },
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::*,
};

struct App {
    is_running: bool,
    data: Vec<DnsData>,
    state: ratatui::widgets::TableState,
}

pub fn run_tui(dns_data: Vec<DnsData>, trace_data: TraceData) -> color_eyre::Result<()> {
    let mut app = App {
        is_running: true,
        data: dns_data,
        state: TableState::default(),
    };
    app.state.select(Some(0));
    let mut terminal = ratatui::init();
    while app.is_running {
        terminal.draw(|f| {
            let chunks = Layout::new(
                Direction::Vertical,
                [
                    Constraint::Min(3),
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ]
                .as_ref(),
            )
            .split(f.area());

            if let Some(ip) = app.data.iter().find(|v| v.type_field == "ip") {
                let ip = ip.clone();
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        ip.ip.italic(),
                        " [".into(),
                        ip.country_name.yellow(),
                        ", ".into(),
                        ip.asn.green(),
                        "]".into(),
                    ]))
                    .block(
                        Block::bordered().title("| Your IP |").title_top(
                            ratatui::text::Span::from("dnsleaktest-tui")
                                .yellow()
                                .bold()
                                .into_right_aligned_line(),
                        ),
                    ),
                    chunks[0],
                );
            }
            let headers = Row::new(vec!["IP".cyan(), "Country".cyan(), "ASN".cyan()]);
            let rows = app
                .data
                .iter()
                .filter(|result| result.type_field == "dns")
                .map(|result| {
                    Row::new(vec![
                        Cell::from(result.ip.clone()),
                        Cell::from(result.country_name.clone()),
                        Cell::from(result.asn.clone()),
                    ])
                })
                .collect::<Vec<Row>>();
            let table = Table::new(
                rows,
                [
                    Constraint::Min(20),
                    Constraint::Min(20),
                    Constraint::Fill(3),
                ]
                .as_ref(),
            )
            .header(headers)
            .highlight_style(Style::default().bg(Color::White).fg(Color::Black))
            .highlight_symbol("> ")
            .block(
                Block::bordered().title("| DNS Leak Test |").title_bottom(
                    app.data
                        .iter()
                        .find(|v| v.type_field == "conclusion")
                        .map(|v| v.ip.clone().italic())
                        .unwrap_or_default()
                        .into_right_aligned_line(),
                ),
            );
            f.render_stateful_widget(table, chunks[1], &mut app.state);

            let headers = Row::new(vec![
                "TTL".cyan(),
                "Host".cyan(),
                "Address".cyan(),
                "Samples".cyan(),
            ]);

            let mut rows = Vec::new();
            trace_data.hops(|hop| {
                let ttl = hop.ttl().unwrap_or_default();
                let host = hop.host();
                let address = hop.address();
                let samples = hop.samples();
                rows.push(Row::new(vec![
                    Cell::from(ttl),
                    Cell::from(host),
                    Cell::from(address),
                    Cell::from(samples),
                ]));
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Max(5),
                    Constraint::Max(20),
                    Constraint::Max(15),
                    Constraint::Fill(1),
                ]
                .as_ref(),
            )
            .header(headers)
            .highlight_style(Style::default().bg(Color::White).fg(Color::Black))
            .highlight_symbol("> ")
            .block(Block::bordered().title(format!("| {} |", trace_data.summary().italic())));

            f.render_widget(table, chunks[2]);
        })?;

        let event = crossterm::event::read()?;
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Char('q') => {
                    app.is_running = false;
                }
                KeyCode::Down => {
                    app.state.select_next();
                }
                KeyCode::Up => {
                    app.state.select_previous();
                }
                _ => {}
            }
        }
    }
    ratatui::restore();
    Ok(())
}
