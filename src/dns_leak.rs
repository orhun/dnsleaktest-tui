use serde::{Deserialize, Serialize};
const API_URL: &str = "bash.ws";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsData {
    pub ip: String,
    pub country: String,
    #[serde(rename = "country_name")]
    pub country_name: String,
    pub asn: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

pub fn test_dns_leak() -> color_eyre::Result<Vec<DnsData>> {
    let id = reqwest::blocking::get(&format!("https://{API_URL}/id"))?.text()?;

    let attempts = 0..10;
    attempts.into_iter().for_each(|i| {
        let _ = reqwest::blocking::get(&format!("https://{i}.{id}.{API_URL}")).ok();
    });

    let mut data: Vec<DnsData> =
        reqwest::blocking::get(&format!("https://{API_URL}/dnsleak/test/{id}?json"))?.json()?;

    data.iter_mut().for_each(|result| {
        result.country_name = format!(
            "{} {}",
            result.country_name,
            country_emoji::flag(&result.country).unwrap_or_else(|| "?".to_string())
        );
    });

    Ok(data)
}
