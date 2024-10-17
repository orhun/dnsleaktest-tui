use clap::Parser;

pub mod dns_leak;
pub mod trace;
pub mod tui;

#[derive(Debug, Parser)]
#[clap(name = "dnsleaktest-tui", about)]
struct Opt {
    #[clap(
        long = "hostname",
        default_value = "discord.com",
        value_name = "STRING"
    )]
    hostname: String,
}

fn main() -> color_eyre::Result<()> {
    let opt = Opt::parse();
    let hostname = opt.hostname;

    println!("Collecting DNS leak test data...");
    let dns_data = dns_leak::test_dns_leak()?;

    println!("Running traceroute...");
    let trace_data = trace::traceroute(hostname.as_str())?;
    tui::run_tui(dns_data, trace_data)?;

    Ok(())
}
