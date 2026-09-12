use clap::Args;

#[derive(Args)]
pub struct RequestProdArgs {
    #[arg(long)]
    pub website: Option<String>,
    #[arg(long)]
    pub contact: Option<String>,
}

pub async fn run(args: RequestProdArgs) -> anyhow::Result<()> {
    let website = match args.website {
        Some(w) => w,
        None => inquire::Text::new("Project website URL").prompt()?,
    };
    let contact = match args.contact {
        Some(c) => c,
        None => inquire::Text::new("Operations contact email").prompt()?,
    };
    let description = format!(
        "Transactional email for {website}. Automated bounce/complaint handling via SES reputation alarms, \
         transactional account events only (verification codes, receipts, alerts), double opt-in for any marketing. \
         Contact: {contact}."
    );
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ses = aws_sdk_sesv2::Client::new(&config);
    ses.put_account_details()
        .mail_type(aws_sdk_sesv2::types::MailType::Transactional)
        .website_url(&website)
        .contact_language("EN".into())
        .use_case_description(&description)
        .additional_contact_email_addresses(&contact)
        .production_access_enabled(true)
        .send()
        .await?;
    println!("production access request submitted for {website}");
    Ok(())
}
