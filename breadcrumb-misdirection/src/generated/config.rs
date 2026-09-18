use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "alertHeader")]
    pub alert_header: String,
    #[serde(alias = "breadcrumb")]
    pub breadcrumb: String,
    #[serde(alias = "mode")]
    pub mode: String,
    #[serde(alias = "seedToolDescriptions")]
    pub seed_tool_descriptions: bool,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
