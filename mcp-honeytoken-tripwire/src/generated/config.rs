use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "alertHeader")]
    pub alert_header: String,
    #[serde(alias = "caseSensitive")]
    pub case_sensitive: bool,
    #[serde(alias = "decoyIds")]
    pub decoy_ids: Option<Vec<String>>,
    #[serde(alias = "honeytokens")]
    pub honeytokens: Vec<String>,
    #[serde(alias = "mode")]
    pub mode: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
