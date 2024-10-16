use std::time::Duration;

use itertools::Itertools;
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
use serde::{Deserialize, Serialize};
use trippy::core::{Builder, PortDirection, Protocol};
use trippy::dns::{Config, DnsResolver, Resolver};

const API_URL: &str = "bash.ws";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsData {
    pub ip: String,
    pub country: String,
    #[serde(rename = "country_name")]
    pub country_name: String,
    pub asn: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

fn test_dns_leak() -> color_eyre::Result<Vec<DnsData>> {
    let agent = ureq::Agent::new();
    let id = agent
        .get(&format!("https://{API_URL}/id"))
        .call()?
        .into_string()?;

    for i in 0..10 {
        let _ = agent.get(&format!("https://{i}.{id}.{API_URL}")).call();
    }

    let mut data: Vec<DnsData> = agent
        .get(&format!("https://{API_URL}/dnsleak/test/{id}?json"))
        .call()?
        .into_json()?;

    data.iter_mut().for_each(|result| {
        result.country_name = format!(
            "{} {}",
            result.country_name,
            country_emoji::flag(&result.country).unwrap_or_else(|| "?".to_string())
        );
    });

    Ok(data)
}

struct TraceData {
    summary: String,
    hops: Vec<Hop>,
}

#[derive(Clone)]
struct Hop {
    ttl: Option<String>,
    host: Option<String>,
    address: Option<String>,
    samples: String,
}

fn traceroute(hostname: &str) -> color_eyre::Result<TraceData> {
    let interface = None::<String>;
    let src_addr = None;
    let port = 33434;
    let first_ttl = 1;
    let max_ttl = 64;
    let nqueries = 3;
    let tos = 0;
    let pausemecs = 100;
    let port_direction = PortDirection::new_fixed_src(port);
    let resolver = DnsResolver::start(Config::default())?;
    let addrs: Vec<_> = resolver
        .lookup(hostname)
        .map_err(|_| color_eyre::eyre::eyre!(format!("traceroute: unknown host {}", hostname)))?
        .into_iter()
        .collect();
    let addr = match addrs.as_slice() {
        [] => {
            return Err(color_eyre::eyre::eyre!(
                "traceroute: unknown host {}",
                hostname
            ))
        }
        [addr] => *addr,
        [addr, ..] => {
            println!("traceroute: Warning: {hostname} has multiple addresses; using {addr}");
            *addr
        }
    };
    let tracer = Builder::new(addr)
        .interface(interface)
        .source_addr(src_addr)
        .protocol(Protocol::Udp)
        .port_direction(port_direction)
        .packet_size(52)
        .first_ttl(first_ttl)
        .max_ttl(max_ttl)
        .tos(tos)
        .max_flows(1)
        .max_rounds(Some(nqueries))
        .min_round_duration(Duration::from_millis(pausemecs))
        .max_round_duration(Duration::from_millis(pausemecs))
        .build()?;
    tracer.run()?;
    let snapshot = &tracer.snapshot();
    if let Some(err) = snapshot.error() {
        return Err(color_eyre::eyre::eyre!("error: {err}"));
    }
    let mut hops = Vec::new();
    for hop in snapshot.hops() {
        let ttl = hop.ttl();
        let samples: String = hop
            .samples()
            .iter()
            .map(|s| format!("{:.3} ms", s.as_secs_f64() * 1000_f64))
            .join("  ");
        if hop.addr_count() > 0 {
            for (i, addr) in hop.addrs().enumerate() {
                let host = resolver.reverse_lookup(*addr).to_string();
                if i != 0 {
                    hops.push(Hop {
                        ttl: None,
                        host: Some(host),
                        address: Some(addr.to_string()),
                        samples: samples.clone(),
                    });
                } else {
                    hops.push(Hop {
                        ttl: Some(ttl.to_string()),
                        host: Some(host),
                        address: Some(addr.to_string()),
                        samples: samples.clone(),
                    });
                }
            }
        } else {
            hops.push(Hop {
                ttl: Some(ttl.to_string()),
                host: None,
                address: None,
                samples: samples.clone(),
            });
        }
    }
    Ok(TraceData {
        summary: format!(
            "Traceroute to {} ({}), {} hops max, {} byte packets",
            &hostname,
            tracer.target_addr(),
            tracer.max_ttl().0,
            tracer.packet_size().0
        ),
        hops,
    })
}

struct App {
    is_running: bool,
    data: Vec<DnsData>,
    state: TableState,
}

fn run_tui(dns_data: Vec<DnsData>, trace_data: TraceData) -> color_eyre::Result<()> {
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
                    .block(Block::bordered().title("| Your IP |")),
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
            for hop in trace_data.hops.clone() {
                let ttl = hop.ttl.unwrap_or_default();
                let host = hop.host.unwrap_or_else(|| "*".to_string());
                let address = hop.address.unwrap_or_else(|| "*".to_string());
                let samples = hop.samples;
                rows.push(Row::new(vec![
                    Cell::from(ttl),
                    Cell::from(host),
                    Cell::from(address),
                    Cell::from(samples),
                ]));
            }
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
            .block(Block::bordered().title(format!("| {} |", trace_data.summary.clone().italic())));
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

fn main() -> color_eyre::Result<()> {
    println!("Collecting DNS leak test data...");
    let dns_data = test_dns_leak()?;
    println!("Running traceroute...");
    let trace_data = traceroute("discord.com")?;
    run_tui(dns_data, trace_data)?;
    Ok(())
}
