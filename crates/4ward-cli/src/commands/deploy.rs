use super::{load_config, TEMPLATE};
use clap::Args;
use comfy_table::Table;

#[derive(Args)]
pub struct DeployArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[arg(long)]
    pub yes: bool,
    /// Skip pushing built Lambda code (infra only)
    #[arg(long)]
    pub no_code: bool,
}

#[derive(Args)]
pub struct DestroyArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
    #[arg(long)]
    pub yes: bool,
}

fn slug(domain: &str) -> String {
    domain.replace('.', "-")
}

fn stack_for(cfg: &fourward_core::FourwardConfig, domain: &str) -> String {
    if cfg.domains.len() == 1 {
        cfg.aws.stack_name.clone()
    } else {
        format!("{}-{}", cfg.aws.stack_name, slug(domain))
    }
}

fn alias_map_json(cfg: &fourward_core::FourwardConfig, domain: &str) -> String {
    let mut m = std::collections::HashMap::new();
    for d in &cfg.domains {
        if d.domain.eq_ignore_ascii_case(domain) {
            for (a, dests) in &d.routes {
                m.insert(format!("{a}@{}", d.domain), dests.clone());
            }
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
    println!("aws account: {}", id.account().unwrap_or("?"));

    // 2. Build lambdas once (best-effort); zips reused for every domain stack.
    let zips = if args.no_code { Vec::new() } else { try_build_lambdas() };

    let cf = aws_sdk_cloudformation::Client::new(&aws_cfg);
    for d in &cfg.domains {
        deploy_one(&cf, &aws_cfg, &cfg, d, &zips).await?;
    }
    // 3. DNS: Route53 note or ASCII table for external.
    sync_dns(&aws_cfg, &cfg).await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn deploy_one(
    cf: &aws_sdk_cloudformation::Client,
    aws_cfg: &aws_config::SdkConfig,
    cfg: &fourward_core::FourwardConfig,
    d: &fourward_core::DomainConfig,
    zips: &[(String, Vec<u8>)],
) -> anyhow::Result<()> {
    let stack = stack_for(cfg, &d.domain);
    let (arc_selector, arc_key) = detect_arc(aws_cfg, &d.domain).await;
    let params = vec![
        ("ProjectName", stack.clone()),
        ("DomainName", d.domain.clone()),
        ("RelayDomain", d.domain.clone()),
        ("AliasMapJson", alias_map_json(cfg, &d.domain)),
        ("CatchAll", d.catch_all.clone().unwrap_or_default()),
        ("BannerEnabled", cfg.settings.banner_enabled.to_string()),
        ("ApiEnabled", cfg.api.enabled.to_string()),
        ("AllowedDomains", cfg.domains.iter().map(|d| d.domain.clone()).collect::<Vec<_>>().join(",")),
        ("RetentionDays", cfg.settings.retention_days.to_string()),
        ("RateLimit", cfg.api.rate_limit.requests_per_second.to_string()),
        ("Burst", cfg.api.rate_limit.burst.to_string()),
        ("ArcSelector", arc_selector),
        ("ArcKeySsm", arc_key),
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

    let exists = cf.describe_stacks().stack_name(&stack).send().await.is_ok();
    if exists {
        println!("updating stack {stack}…");
        let r = cf.update_stack()
            .stack_name(&stack)
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
                } else {
                    return Err(e.into());
                }
            }
        }
    } else {
        println!("creating stack {stack}…");
        cf.create_stack()
            .stack_name(&stack)
            .template_body(TEMPLATE)
            .set_parameters(Some(parameters))
            .capabilities(aws_sdk_cloudformation::types::Capability::CapabilityIam)
            .send()
            .await?;
    }
    println!("waiting for {stack}…");
    // Simple poll loop instead of waiters (fewer deps).
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        if let Ok(o) = cf.describe_stacks().stack_name(&stack).send().await {
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
    // 4. Push real Lambda code (template ships a placeholder otherwise).
    if !zips.is_empty() {
        push_code(aws_cfg, &stack).await;
    }
    Ok(())
}

/// ARC auto-detect: `keys arc` stores PEM at /4ward/arc/<domain> (+ selector).
async fn detect_arc(aws_cfg: &aws_config::SdkConfig, domain: &str) -> (String, String) {
    let ssm = aws_sdk_ssm::Client::new(aws_cfg);
    let key = format!("/4ward/arc/{domain}");
    if ssm.get_parameter().name(&key).with_decryption(true).send().await.is_err() {
        return (String::new(), String::new());
    }
    let sel = ssm.get_parameter().name(format!("{key}/selector")).send().await.ok()
        .and_then(|o| o.parameter().and_then(|p| p.value().map(|s| s.to_string())))
        .unwrap_or_else(|| "fw1".to_string());
    println!("ARC key found for {domain} (selector {sel})");
    (sel, key)
}

/// Build both lambdas to bootstrap.zip; returns (func_suffix, zip_bytes).
fn try_build_lambdas() -> Vec<(String, Vec<u8>)> {
    let ok = std::process::Command::new("cargo").arg("lambda").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        println!("cargo-lambda not found — deploying with placeholder code; run `cargo install cargo-lambda` for real traffic");
        return Vec::new();
    }
    let mut out = Vec::new();
    for (pkg, func) in [("lambda-forwarder", "forwarder"), ("lambda-api", "api")] {
        println!("building {pkg} (arm64)…");
        let st = std::process::Command::new("cargo").args(["lambda", "build", "--arm64", "--release", "--package", pkg, "--output-format", "zip"]).status();
        match st {
            Ok(s) if s.success() => {
                let zip = format!("target/lambda/{pkg}/bootstrap.zip");
                match std::fs::read(&zip) {
                    Ok(b) => {
                        println!("{pkg} built ({} bytes)", b.len());
                        out.push((func.to_string(), b));
                    }
                    Err(_) => println!("{pkg} built but {zip} missing — placeholder kept"),
                }
            }
            _ => println!("{pkg} build failed — continuing with placeholder"),
        }
    }
    out
}

async fn push_code(aws_cfg: &aws_config::SdkConfig, stack: &str) {
    let lambda = aws_sdk_lambda::Client::new(aws_cfg);
    // zips rebuilt per deploy; re-read from disk (single source of truth).
    for (pkg, func) in [("lambda-forwarder", "forwarder"), ("lambda-api", "api")] {
        let zip = format!("target/lambda/{pkg}/bootstrap.zip");
        let bytes = match std::fs::read(&zip) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let name = format!("{stack}-{func}");
        println!("updating code for {name}…");
        match lambda.update_function_code().function_name(&name).zip_file(aws_sdk_lambda::primitives::Blob::new(bytes)).send().await {
            Ok(_) => println!("{name} updated"),
            Err(e) => println!("{name} code update failed: {e:?} (infra is live with previous code)"),
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
    let stacks: Vec<String> = cfg.domains.iter().map(|d| stack_for(&cfg, &d.domain)).collect();
    if !args.yes {
        let ok = inquire::Confirm::new(&format!("Delete stacks {}?", stacks.join(", "))).with_default(false).prompt()?;
        if !ok {
            println!("aborted");
            return Ok(());
        }
    }
    let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let cf = aws_sdk_cloudformation::Client::new(&aws_cfg);
    for stack in &stacks {
        cf.delete_stack().stack_name(stack).send().await?;
        println!("delete initiated for {stack}");
    }
    Ok(())
}
