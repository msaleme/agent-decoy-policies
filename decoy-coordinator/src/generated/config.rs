use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "breadcrumb")]
    pub breadcrumb: String,
    #[serde(alias = "breadcrumbMode")]
    pub breadcrumb_mode: String,
    #[serde(alias = "caseSensitive")]
    pub case_sensitive: bool,
    #[serde(alias = "decoyTools")]
    pub decoy_tools: Vec<String>,
    #[serde(alias = "honeytokenMode")]
    pub honeytoken_mode: String,
    #[serde(alias = "honeytokens")]
    pub honeytokens: Vec<String>,
    #[serde(alias = "seeding")]
    pub seeding: String,
    #[serde(alias = "sentinelMode")]
    pub sentinel_mode: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
