use super::load_config;
use clap::Args;
use comfy_table::Table;

#[derive(Args)]
pub struct DnsArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[arg(long, default_value = "table", value_parser = ["table", "json", "bind"])]
    pub format: String,
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
}

pub async fn run(args: DnsArgs) -> anyhow::Result<()> {
    let cfg = load_config(&args.config).unwrap_or_else(|_| {
        // Allow `4ward dns` with explicit domain-less fallback? Require config.
        eprintln!("cannot load config, using empty");
        std::process::exit(1);
    });
    let region = if cfg.aws.region.is_empty() { args.region } else { cfg.aws.region.clone() };
    // Try live DKIM tokens via SES; fall back to placeholders (external DNS pre-deploy).
    let tokens = fetch_dkim_tokens(&cfg.domains.first().map(|d| d.domain.clone()).unwrap_or_default(), &region).await
        .unwrap_or_else(fourward_core::placeholder_dkim_tokens);

    let mut all = Vec::new();
    for d in &cfg.domains {
        all.extend(fourward_core::records_for_domain(&d.domain, &region, &tokens));
    }
    match args.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&all)?),
        "bind" => {
            for r in &all {
                println!("{}.\t{}\tIN\t{}\t{}", r.name, r.ttl, r.record_type, r.value);
            }
        }
        _ => {
            let mut t = Table::new();
            t.set_header(vec!["Type", "Name", "Value", "Purpose"]);
            for r in &all {
                t.add_row(vec![r.record_type.clone(), r.name.clone(), r.value.clone(), r.purpose.clone()]);
            }
            println!("{t}");
        }
    }
    Ok(())
}

async fn fetch_dkim_tokens(domain: &str, region: &str) -> Option<Vec<String>> {
    if domain.is_empty() {
        return None;
    }
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_sesv2::Client::new(&config);
    let _ = region;
    let out = client.get_email_identity().email_identity(domain).send().await.ok()?;
    out.dkim_attributes()
        .map(|d| d.tokens().to_vec())
        .filter(|t| t.len() == 3)
}
