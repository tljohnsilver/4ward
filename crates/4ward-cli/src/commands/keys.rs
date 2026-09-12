use clap::{Args, Subcommand};

#[derive(Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub cmd: KeyCmd,
}

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate Bearer token and store in SSM at /4ward/api-keys/<name>
    Create {
        name: String,
        #[arg(long, default_value = "/4ward/api-keys/")]
        prefix: String,
    },
    /// List key names under prefix (names only, never values)
    List {
        #[arg(long, default_value = "/4ward/api-keys/")]
        prefix: String,
    },
    /// Delete a key
    Revoke {
        name: String,
        #[arg(long, default_value = "/4ward/api-keys/")]
        prefix: String,
    },
}

pub async fn run(args: KeysArgs) -> anyhow::Result<()> {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ssm = aws_sdk_ssm::Client::new(&config);
    match args.cmd {
        KeyCmd::Create { name, prefix } => {
            let token = gen_token();
            ssm.put_parameter()
                .name(format!("{prefix}{name}"))
                .value(&token)
                .r#type(aws_sdk_ssm::types::ParameterType::SecureString)
                .overwrite(true)
                .send()
                .await?;
            println!("{token}");
            eprintln!("stored at {prefix}{name} — copy it now, it won't be shown again");
        }
        KeyCmd::List { prefix } => {
            let out = ssm.describe_parameters()
                .parameter_filters(aws_sdk_ssm::types::ParameterStringFilter::builder().key("Name").option("BeginsWith").values(&prefix).build()?)
                .send().await?;
            for p in out.parameters() {
                println!("{}", p.name().unwrap_or(""));
            }
        }
        KeyCmd::Revoke { name, prefix } => {
            ssm.delete_parameter().name(format!("{prefix}{name}")).send().await?;
            println!("revoked {prefix}{name}");
        }
    }
    Ok(())
}

fn gen_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("4w_live_{}", hex::encode(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_shape() {
        let t = gen_token();
        assert!(t.starts_with("4w_live_"));
        assert_eq!(t.len(), "4w_live_".len() + 32);
    }
}
