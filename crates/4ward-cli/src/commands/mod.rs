pub mod alias;
pub mod deploy;
pub mod dns;
pub mod init;
pub mod keys;
pub mod request_prod;
pub mod status;

pub const TEMPLATE: &str = include_str!("../../templates/template.yaml");

pub fn load_config(path: &str) -> anyhow::Result<fourward_core::FourwardConfig> {
    let s = std::fs::read_to_string(path).map_err(|_| anyhow::anyhow!("config not found: {path} (run `4ward init`)"))?;
    fourward_core::FourwardConfig::from_json(&s).map_err(|e| anyhow::anyhow!("{e}"))
}
