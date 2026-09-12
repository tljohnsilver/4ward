use clap::{Args, Subcommand};

#[derive(Args)]
pub struct AliasArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[command(subcommand)]
    pub cmd: AliasCmd,
}

#[derive(Subcommand)]
pub enum AliasCmd {
    /// List all alias routes
    List,
    /// Add/update an alias route: alias@domain -> dest1,dest2
    Set { route: String, dests: String },
    /// Remove an alias route
    Rm { route: String },
}

pub async fn run(args: AliasArgs) -> anyhow::Result<()> {
    let s = std::fs::read_to_string(&args.config)?;
    let mut cfg = fourward_core::FourwardConfig::from_json(&s).map_err(|e| anyhow::anyhow!("{e}"))?;
    match args.cmd {
        AliasCmd::List => {
            for d in &cfg.domains {
                for (a, dests) in &d.routes {
                    println!("{a}@{} -> {}", d.domain, dests.join(","));
                }
                if let Some(c) = &d.catch_all {
                    println!("*@{} -> {c} (catch-all)", d.domain);
                }
            }
        }
        AliasCmd::Set { route, dests } => {
            let (alias, domain) = route.split_once('@').ok_or_else(|| anyhow::anyhow!("route must be alias@domain"))?;
            let dests: Vec<String> = dests.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            let d = cfg.domains.iter_mut().find(|d| d.domain.eq_ignore_ascii_case(domain))
                .ok_or_else(|| anyhow::anyhow!("domain {domain} not in config"))?;
            d.routes.insert(alias.to_lowercase(), dests);
            std::fs::write(&args.config, serde_json::to_string_pretty(&cfg)?)?;
            println!("updated {route}");
        }
        AliasCmd::Rm { route } => {
            let (alias, domain) = route.split_once('@').ok_or_else(|| anyhow::anyhow!("route must be alias@domain"))?;
            let d = cfg.domains.iter_mut().find(|d| d.domain.eq_ignore_ascii_case(domain))
                .ok_or_else(|| anyhow::anyhow!("domain {domain} not in config"))?;
            d.routes.remove(&alias.to_lowercase());
            d.routes.remove(alias);
            std::fs::write(&args.config, serde_json::to_string_pretty(&cfg)?)?;
            println!("removed {route}");
        }
    }
    Ok(())
}
