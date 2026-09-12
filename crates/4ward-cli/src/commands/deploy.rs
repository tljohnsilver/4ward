use super::{load_config, TEMPLATE};
use clap::Args;
use comfy_table::Table;

#[derive(Args)]
pub struct DeployArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct DestroyArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[arg(long)]
    pub yes: bool,
}

fn alias_map_json(cfg: &fourward_core::FourwardConfig) -> String {
    let mut m = std::collections::HashMap::new();
    for d in &cfg.domains {
        for (a, dests) in &d.routes {
            m.insert(format!("{a}@{}", d.domain), dests.clone());
        }
    }
    serde_json::to_string(&m).unwrap_or("{}".into())
}

pub async fn run(args: DeployArgs) -> anyhow::Result<()> {
    let cfg = load_config(&args.config)?;
    let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    // 1. Validate session.
    let sts = aws_sdk_sts::Client::new(&aws_cfg);
    let id = sts.get_caller_identity().send().await?;
    println!("aws account: {} — deploying {}", id.account().unwrap_or("?"), cfg.aws.stack_name);

    // 2. Try building lambdas (best-effort; stack deploys with placeholder if toolchain missing).
    try_build_lambdas();

    let cf = aws_sdk_cloudformation::Client::new(&aws_cfg);
    let domain = cfg.domains.first().map(|d| d.domain.clone()).unwrap_or_default();
    let params = vec![
        ("ProjectName", cfg.project.clone()),
        ("DomainName", domain.clone()),
        ("RelayDomain", domain.clone()),
        ("AliasMapJson", alias_map_json(&cfg)),
        ("CatchAll", cfg.domains.first().and_then(|d| d.catch_all.clone()).unwrap_or_default()),
        ("BannerEnabled", cfg.settings.banner_enabled.to_string()),
        ("ApiEnabled", cfg.api.enabled.to_string()),
        ("AllowedDomains", cfg.domains.iter().map(|d| d.domain.clone()).collect::<Vec<_>>().join(",")),
        ("RetentionDays", cfg.settings.retention_days.to_string()),
    ];
    let parameters: Vec<aws_sdk_cloudformation::types::Parameter> = params
        .into_iter()
        .map(|(k, v)| {
            aws_sdk_cloudformation::types::Parameter::builder()
                .parameter_key(k)
                .parameter_value(v)
                .build()
        })
        .collect();

    let exists = cf.describe_stacks().stack_name(&cfg.aws.stack_name).send().await.is_ok();
    if exists {
        println!("updating stack {}…", cfg.aws.stack_name);
        let r = cf.update_stack()
            .stack_name(&cfg.aws.stack_name)
            .template_body(TEMPLATE)
            .set_parameters(Some(parameters))
            .capabilities(aws_sdk_cloudformation::types::Capability::CapabilityIam)
            .send()
            .await;
        match r {
            Ok(_) => println!("update initiated"),
            Err(e) => {
                let s = format!("{e:?}");
                if s.contains("No updates") {
                    println!("no updates to perform");
                    print_dns(&cfg);
                    return Ok(());
                }
                return Err(e.into());
            }
        }
    } else {
        println!("creating stack {}…", cfg.aws.stack_name);
        cf.create_stack()
            .stack_name(&cfg.aws.stack_name)
            .template_body(TEMPLATE)
            .set_parameters(Some(parameters))
            .capabilities(aws_sdk_cloudformation::types::Capability::CapabilityIam)
            .send()
            .await?;
    }
    println!("waiting for stack… (this takes a few minutes)");
    // Simple poll loop instead of waiters (fewer deps).
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        if let Ok(o) = cf.describe_stacks().stack_name(&cfg.aws.stack_name).send().await {
            if let Some(s) = o.stacks().first() {
                let st = format!("{:?}", s.stack_status());
                println!("  status: {st}");
                if st.contains("COMPLETE") && !st.contains("PROGRESS") {
                    break;
                }
                if st.contains("FAILED") || st.contains("ROLLBACK_COMPLETE") {
                    anyhow::bail!("stack failed: {st}");
                }
            }
        }
    }
    // 3. DNS: Route53 auto-update or ASCII table for external.
    sync_dns(&aws_cfg, &cfg).await;
    Ok(())
}

fn try_build_lambdas() {
    let ok = std::process::Command::new("cargo").arg("lambda").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        println!("cargo-lambda not found — deploying with placeholder code; run `cargo install cargo-lambda` + rebuild for real traffic");
        return;
    }
    for pkg in ["lambda-forwarder", "lambda-api"] {
        println!("building {pkg} (arm64)…");
        let st = std::process::Command::new("cargo").args(["lambda", "build", "--arm64", "--release", "--package", pkg]).status();
        match st {
            Ok(s) if s.success() => println!("{pkg} built"),
            _ => println!("{pkg} build failed — continuing with placeholder"),
        }
    }
}

async fn sync_dns(aws_cfg: &aws_config::SdkConfig, cfg: &fourward_core::FourwardConfig) {
    let r53 = aws_sdk_route53::Client::new(aws_cfg);
    for d in &cfg.domains {
        let hosted = r53.list_hosted_zones_by_name().dns_name(&d.domain).send().await.ok()
            .and_then(|o| o.hosted_zones().first().cloned());
        let is_route53 = matches!(d.dns_provider, fourward_core::DnsProvider::Route53) && hosted.is_some();
        if is_route53 {
            println!("Route53 zone found for {} — add MX/SPF/DKIM via `4ward dns --format bind` or console", d.domain);
        } else {
            println!("external DNS for {} — add these records:", d.domain);
            print_dns(cfg);
        }
    }
}

fn print_dns(cfg: &fourward_core::FourwardConfig) {
    let mut t = Table::new();
    t.set_header(vec!["Type", "Name", "Value"]);
    let region = &cfg.aws.region;
    for d in &cfg.domains {
        for r in fourward_core::records_for_domain(&d.domain, region, &fourward_core::placeholder_dkim_tokens()) {
            let val = if r.record_type == "CNAME" && r.value.starts_with("token") {
                format!("{} (see SES console for real DKIM token)", r.value)
            } else {
                r.value.clone()
            };
            t.add_row(vec![r.record_type.clone(), r.name.clone(), val]);
        }
    }
    println!("{t}");
}

pub async fn destroy(args: DestroyArgs) -> anyhow::Result<()> {
    let cfg = load_config(&args.config)?;
    if !args.yes {
        let ok = inquire::Confirm::new(&format!("Delete stack {}?", cfg.aws.stack_name)).with_default(false).prompt()?;
        if !ok {
            println!("aborted");
            return Ok(());
        }
    }
    let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let cf = aws_sdk_cloudformation::Client::new(&aws_cfg);
    cf.delete_stack().stack_name(&cfg.aws.stack_name).send().await?;
    println!("delete initiated for {}", cfg.aws.stack_name);
    Ok(())
}
