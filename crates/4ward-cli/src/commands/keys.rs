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
    /// Generate ARC seal RSA keypair for a domain (deploy auto-wires it)
    Arc {
        domain: String,
        #[arg(long, default_value = "fw1")]
        selector: String,
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
        KeyCmd::Arc { domain, selector } => {
            let (pem, pub_b64) = gen_arc_keypair()?;
            let key_param = format!("/4ward/arc/{domain}");
            ssm.put_parameter().name(&key_param).value(&pem)
                .r#type(aws_sdk_ssm::types::ParameterType::SecureString)
                .overwrite(true).send().await?;
            ssm.put_parameter().name(format!("{key_param}/selector")).value(&selector)
                .r#type(aws_sdk_ssm::types::ParameterType::String)
                .overwrite(true).send().await?;
            let rec = fourward_core::arc_record(&selector, &domain, &pub_b64);
            println!("private key → {key_param} (deploy wires it automatically)");
            println!("add this DNS record:\n{} TXT {} \"{}\"", rec.name, rec.ttl, rec.value);
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

/// Generate RSA-2048 ARC seal keypair. Returns (private PEM, public DER base64).
pub fn gen_arc_keypair() -> anyhow::Result<(String, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
    let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?.to_string();
    let der_b64 = B64.encode(key.to_public_key().to_pkcs1_der()?.as_bytes());
    Ok((pem, der_b64))
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
    #[test]
    fn arc_keypair_shape() {
        let (pem, b64) = gen_arc_keypair().unwrap();
        assert!(pem.contains("BEGIN RSA PRIVATE KEY"));
        assert!(b64.len() > 200);
    }
}
