use itertools::Itertools;
use std::time::Duration;
use trippy::core::{Builder, PortDirection, Protocol};
use trippy::dns::{Config, DnsResolver, Resolver};

pub struct TraceData {
    summary: String,
    hops: Vec<Hop>,
}

impl TraceData {
    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn hops<F>(&self, mut f: F)
    where
        F: FnMut(&Hop),
    {
        for hop in &self.hops {
            f(hop);
        }
    }
}

#[derive(Clone)]
pub struct Hop {
    ttl: Option<String>,
    host: Option<String>,
    address: Option<String>,
    samples: String,
}

impl Hop {
    pub fn ttl(&self) -> Option<String> {
        self.ttl.as_deref().unwrap_or_default().parse().ok()
    }

    pub fn host(&self) -> String {
        self.host.as_deref().unwrap_or("*").to_string()
    }

    pub fn address(&self) -> String {
        self.address.as_deref().unwrap_or("*").to_string()
    }

    pub fn samples(&self) -> String {
        self.samples.to_string()
    }
}

pub fn traceroute(hostname: &str) -> color_eyre::Result<TraceData> {
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
