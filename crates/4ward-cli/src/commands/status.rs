use clap::Args;

#[derive(Args)]
pub struct StatusArgs {
    #[arg(long, default_value = "4ward.json")]
    pub config: String,
}

pub async fn run(_args: StatusArgs) -> anyhow::Result<()> {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ses = aws_sdk_sesv2::Client::new(&config);
    let acct = ses.get_account().send().await?;
    let sandbox = !acct.production_access_enabled();
    println!("Sandbox mode: {}", if sandbox { "YES (request-production to lift)" } else { "NO (production)" });
    match acct.send_quota() {
        Some(q) => println!("24h quota: {q:?}"),
        None => println!("24h quota: n/a"),
    }
    println!("Enforcement: {:?}", acct.enforcement_status().map(|s| format!("{s:?}")));
    Ok(())
}
