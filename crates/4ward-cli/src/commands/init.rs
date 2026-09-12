use clap::Args;
use fourward_core::{ApiConfig, AwsConfig, DomainConfig, DnsProvider, EngineSettings, FourwardConfig, RateLimitConfig};
use std::collections::HashMap;

#[derive(Args)]
pub struct InitArgs {
    #[arg(long, default_value = "4ward.json")]
    pub output: String,
}

pub async fn run(args: InitArgs) -> anyhow::Result<()> {
    let domain = inquire::Text::new("Primary domain (e.g. example.com)").prompt()?;
    let region = inquire::Text::new("AWS region").with_default("us-east-1").prompt()?;
    let stack = inquire::Text::new("Stack name").with_default(&format!("4ward-{}", domain.replace('.', "-"))).prompt()?;
    let alias = inquire::Text::new("First alias (local part)").with_default("hello").prompt()?;
    let dest = inquire::Text::new("Where should it forward to?").prompt()?;
    let dns_provider = inquire::Select::new("DNS provider", vec!["route53", "external"]).prompt()?.to_string();

    let mut routes = HashMap::new();
    routes.insert(alias, vec![dest]);
    let cfg = FourwardConfig {
        version: "1".into(),
        project: "4ward".into(),
        aws: AwsConfig { region, profile: "default".into(), stack_name: stack },
        api: ApiConfig { enabled: true, cors: vec!["*".into()], rate_limit: RateLimitConfig { requests_per_second: 100, burst: 200 } },
        settings: EngineSettings { banner_enabled: true, retention_days: 1, sender_format: "{name} (via {alias}) <relay@{domain}>".into() },
        domains: vec![DomainConfig {
            domain,
            dns_provider: if dns_provider == "route53" { DnsProvider::Route53 } else { DnsProvider::External },
            catch_all: None,
            routes,
        }],
    };
    cfg.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(&args.output, serde_json::to_string_pretty(&cfg)?)?;
    println!("wrote {}", args.output);
    Ok(())
}
