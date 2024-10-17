pub mod dns_leak;
pub mod trace;
pub mod tui;

fn main() -> color_eyre::Result<()> {
    println!("Collecting DNS leak test data...");
    let dns_data = dns_leak::test_dns_leak()?;

    println!("Running traceroute...");
    let trace_data = trace::traceroute("discord.com")?;
    tui::run_tui(dns_data, trace_data)?;

    Ok(())
}
