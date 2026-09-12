mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "4ward", version, about = "Serverless email infrastructure for AWS in Rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive questionnaire — writes validated 4ward.json
    Init(commands::init::InitArgs),
    /// Compile lambdas (if cargo-lambda present) + deploy CloudFormation stack
    Deploy(commands::deploy::DeployArgs),
    /// SES sandbox, quota & bounce inspector
    Status(commands::status::StatusArgs),
    /// Automated SES production access request (sesv2:PutAccountDetails)
    RequestProduction(commands::request_prod::RequestProdArgs),
    /// DNS export (table, json, bind)
    Dns(commands::dns::DnsArgs),
    /// Bearer token manager (SSM /4ward/api-keys/*)
    Keys(commands::keys::KeysArgs),
    /// Hot alias routing editor (edits 4ward.json routes)
    Alias(commands::alias::AliasArgs),
    /// Tear down the CloudFormation stack
    Destroy(commands::deploy::DestroyArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init(a) => commands::init::run(a).await,
        Commands::Deploy(a) => commands::deploy::run(a).await,
        Commands::Status(a) => commands::status::run(a).await,
        Commands::RequestProduction(a) => commands::request_prod::run(a).await,
        Commands::Dns(a) => commands::dns::run(a).await,
        Commands::Keys(a) => commands::keys::run(a).await,
        Commands::Alias(a) => commands::alias::run(a).await,
        Commands::Destroy(a) => commands::deploy::destroy(a).await,
    }
}
