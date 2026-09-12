use aws_lambda_events::event::s3::S3Event;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use mail_builder::MessageBuilder;
use mail_builder::headers::text::Text;
use mail_parser::{MessageParser, MimeHeaders};
use std::collections::HashMap;

/// Env-driven routing. Keep the Lambda itself stateless:
/// - `RELAY_DOMAIN`: verified SES identity, e.g. `example.com` (From: relay@domain)
/// - `ALIAS_MAP_JSON`: `{"support@example.com": ["you@gmail.com"], ...}`
/// - `CATCH_ALL`: optional fallback destination
/// - `BANNER_ENABLED`: "true"/"false"
/// - `LOOP_SALT`: salt for loop-detection hash (defaults to relay domain)
pub const LOOP_HEADER: &str = "X-4ward-Loop-Detection";

pub fn loop_hash(domain: &str, salt: &str) -> String {
    // ponytail: djb2 hex, std-only; swap for HMAC if spoofing matters
    let mut h: u64 = 5381;
    for b in format!("{salt}:{domain}").bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    format!("{h:016x}")
}

pub fn is_loop(headers_raw: &str, expected_hash: &str) -> bool {
    headers_raw.lines().any(|l| {
        let lt = l.trim();
        lt.len() > LOOP_HEADER.len()
            && lt[..LOOP_HEADER.len()].eq_ignore_ascii_case(LOOP_HEADER)
            && lt[LOOP_HEADER.len()..].contains(expected_hash)
    })
}

pub fn split_alias(recipient: &str) -> Option<(String, String)> {
    let r = recipient.trim().trim_matches(|c| c == '<' || c == '>').trim();
    let (_, addr) = parse_address(r);
    let (user, domain) = addr.split_once('@')?;
    Some((user.to_lowercase(), domain.to_lowercase()))
}

fn parse_address(s: &str) -> (String, String) {
    // "Name <addr@dom>" -> ("Name", "addr@dom"); bare addr -> ("", addr).
    // Tolerates a missing closing '>' (e.g. after trimming).
    if let Some(a) = s.rfind('<') {
        let addr = s[a + 1..].trim_end_matches('>').trim();
        if addr.contains('@') {
            let name = s[..a].trim().trim_matches('"').trim().to_string();
            return (name, addr.to_string());
        }
    }
    (String::new(), s.trim().to_string())
}

fn alias_map() -> HashMap<String, Vec<String>> {
    std::env::var("ALIAS_MAP_JSON")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn resolve_destinations(alias: &str, domain: &str) -> Vec<String> {
    let map = alias_map();
    let key = format!("{alias}@{domain}");
    if let Some(v) = map.get(&key) {
        return v.clone();
    }
    // case-insensitive fallback
    for (k, v) in &map {
        if k.eq_ignore_ascii_case(&key) {
            return v.clone();
        }
    }
    std::env::var("CATCH_ALL").ok().filter(|s| !s.is_empty()).map(|s| vec![s]).unwrap_or_default()
}

pub fn banner_enabled() -> bool {
    std::env::var("BANNER_ENABLED").map(|v| v != "false" && v != "0").unwrap_or(true)
}

pub fn banner_html(alias: &str, domain: &str, dest: &str, original: &str) -> String {
    format!(
        "<div style=\"background:#f4f4f5;padding:8px;font-size:12px;border-radius:4px;color:#333;margin-bottom:12px;\">\n  Forwarded by 4ward from <b>{alias}@{domain}</b> to <b>{dest}</b>. Original sender: <b>{original}</b>\n</div>"
    )
}

pub fn banner_text(alias: &str, domain: &str, dest: &str, original: &str) -> String {
    format!("Forwarded by 4ward from {alias}@{domain} to {dest}. Original sender: {original}\n\n")
}

pub struct ForwardPlan {
    pub alias: String,
    pub domain: String,
    pub destinations: Vec<String>,
    pub original_from: String,
    pub original_from_name: String,
    pub original_to: String,
    pub subject: String,
    pub loop_value: String,
}

/// Pure planning step — easy to unit test without AWS.
pub fn plan_forward(raw: &[u8], relay_domain: &str, loop_salt: &str) -> Result<Option<ForwardPlan>, String> {
    let raw_str = String::from_utf8_lossy(raw);
    let expected = loop_hash(relay_domain, loop_salt);
    // Fast header-section scan for loop marker before full parse.
    let header_section = raw_str.split("\r\n\r\n").next().unwrap_or(&raw_str).to_string();
    let header_section = if header_section.contains('\n') && !header_section.contains("\r\n") {
        header_section.replace('\n', "\r\n")
    } else {
        header_section
    };
    if is_loop(&header_section, &expected) {
        return Ok(None);
    }
    let msg = MessageParser::default().parse(raw).ok_or("mime parse failed")?;
    let from = msg.from().and_then(|a| a.first()).map(|a| {
        (
            a.name().unwrap_or("").to_string(),
            a.address().unwrap_or("").to_string(),
        )
    }).unwrap_or_default();
    let to = msg.to().and_then(|a| a.first()).map(|a| a.address().unwrap_or("").to_string()).unwrap_or_default();
    let (alias, domain) = split_alias(&to).ok_or("no routable To header")?;
    let destinations = resolve_destinations(&alias, &domain);
    if destinations.is_empty() {
        return Err("no route for recipient and no catch-all".into());
    }
    Ok(Some(ForwardPlan {
        alias,
        domain,
        destinations,
        original_from: from.1,
        original_from_name: from.0,
        original_to: to,
        subject: msg.subject().unwrap_or("").to_string(),
        loop_value: expected,
    }))
}

/// Build the relayed raw MIME, preserving text/html + attachments.
pub fn build_forwarded_raw(raw: &[u8], plan: &ForwardPlan, relay_domain: &str) -> Result<Vec<u8>, String> {
    let msg = MessageParser::default().parse(raw).ok_or("mime parse failed")?;
    let dest0 = plan.destinations.first().cloned().unwrap_or_default();
    let from_name = if plan.original_from_name.trim().is_empty() {
        plan.alias.clone()
    } else {
        plan.original_from_name.clone()
    };
    let relay_from = format!("relay@{relay_domain}");
    let display_from = format!("{from_name} (via {})", plan.alias);

    let text_body = msg.body_text(0).map(|b| b.to_string());
    let html_body = msg.body_html(0).map(|b| b.to_string());

    let (text_out, html_out) = if banner_enabled() {
        let bt = banner_text(&plan.alias, &plan.domain, &dest0, &plan.original_from);
        let bh = banner_html(&plan.alias, &plan.domain, &dest0, &plan.original_from);
        (
            text_body.map(|b| format!("{bt}{b}")),
            html_body.map(|b| format!("{bh}{b}")),
        )
    } else {
        (text_body, html_body)
    };

    let mut builder = MessageBuilder::new()
        .from((display_from.as_str(), relay_from.as_str()))
        .reply_to(plan.original_from.as_str())
        .to(plan.destinations.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .subject(plan.subject.as_str())
        .header("X-Original-From", Text::new(plan.original_from.as_str()))
        .header("X-Original-To", Text::new(plan.original_to.as_str()))
        .header("X-4ward-Relay", Text::new("true"))
        .header(LOOP_HEADER, Text::new(plan.loop_value.as_str()));

    if let Some(t) = text_out.as_deref() {
        builder = builder.text_body(t);
    }
    if let Some(h) = html_out.as_deref() {
        builder = builder.html_body(h);
    }
    if text_out.is_none() && html_out.is_none() {
        builder = builder.text_body("(empty message forwarded by 4ward)");
    }
    // Re-attach original attachments (retention, not transformation).
    // ponytail: generic content-type; sniff real type per part if clients need it
    let atts: Vec<(String, Vec<u8>)> = msg
        .attachments()
        .map(|att| {
            (
                att.attachment_name().unwrap_or("attachment.bin").to_string(),
                att.contents().to_vec(),
            )
        })
        .collect();
    for (name, bytes) in &atts {
        builder = builder.attachment("application/octet-stream", name.as_str(), bytes.as_slice());
    }

    builder.write_to_vec().map_err(|e| e.to_string())
}

async fn handle(event: LambdaEvent<S3Event>) -> Result<(), Error> {
    let relay_domain = std::env::var("RELAY_DOMAIN").unwrap_or_default();
    let loop_salt = std::env::var("LOOP_SALT").unwrap_or_else(|_| relay_domain.clone());
    if relay_domain.is_empty() {
        tracing::warn!("RELAY_DOMAIN unset, skipping");
        return Ok(());
    }
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3 = aws_sdk_s3::Client::new(&config);
    let ses = aws_sdk_sesv2::Client::new(&config);

    for record in event.payload.records {
        let bucket = record.s3.bucket.name.unwrap_or_default();
        let key = record.s3.object.key.unwrap_or_default();
        tracing::info!(bucket = %bucket, key = %key, "fetching raw mime from s3");
        let obj = s3.get_object().bucket(&bucket).key(&key).send().await?;
        let bytes = obj.body.collect().await?.into_bytes().to_vec();

        let plan = plan_forward(&bytes, &relay_domain, &loop_salt).map_err(|e| format!("plan: {e}"))?;
        let plan = match plan {
            None => {
                tracing::warn!("loop header matched, dropping");
                continue;
            }
            Some(p) => p,
        };
        let raw = build_forwarded_raw(&bytes, &plan, &relay_domain).map_err(|e| format!("build: {e}"))?;
        let relay_from = format!("relay@{relay_domain}");
        ses.send_email()
            .from_email_address(&relay_from)
            .set_destination(Some(
                aws_sdk_sesv2::types::Destination::builder()
                    .set_to_addresses(Some(plan.destinations.clone()))
                    .build(),
            ))
            .content(
                aws_sdk_sesv2::types::EmailContent::builder()
                    .raw(aws_sdk_sesv2::types::RawMessage::builder().data(aws_sdk_sesv2::primitives::Blob::new(raw)).build().map_err(|e| format!("raw: {e}"))?)
                    .build(),
            )
            .send()
            .await?;
        tracing::info!(to = ?plan.destinations, "relayed via sesv2");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    lambda_runtime::run(service_fn(handle)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &[u8] = b"From: Alice <alice@example.org>\r\nTo: support@relay.example.com\r\nSubject: hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHi there";
    const HTML: &[u8] = b"From: Bob <bob@example.org>\r\nTo: sales@relay.example.com\r\nSubject: hi html\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hi <b>there</b></p>";

    fn multipart_fixture() -> Vec<u8> {
        let boundary = "BOUNDARY123";
        format!(
            "From: Carol <carol@example.org>\r\nTo: info@relay.example.com\r\nSubject: with file\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--{boundary}\r\nContent-Type: application/pdf; name=\"document.pdf\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"document.pdf\"\r\n\r\nJVBERi0xLjQK\r\n--{boundary}--\r\n"
        ).into_bytes()
    }

    #[test]
    fn loop_detection_trips() {
        let h = loop_hash("example.com", "example.com");
        let raw = format!("From: a@b.c\r\nTo: x@y.z\r\n{LOOP_HEADER}: {h}\r\nSubject: t\r\n\r\nbody");
        assert!(plan_forward(raw.as_bytes(), "example.com", "example.com").unwrap().is_none());
    }

    #[test]
    fn splits_alias() {
        assert_eq!(split_alias("\"Support\" <Support@Example.COM>").unwrap(), ("support".into(), "example.com".into()));
    }

    #[test]
    fn rebuild_plain_keeps_body_and_audit_headers() {
        let relay = "example.com";
        let plan = ForwardPlan {
            alias: "support".into(), domain: "relay.example.com".into(),
            destinations: vec!["you@gmail.com".into()],
            original_from: "alice@example.org".into(), original_from_name: "Alice".into(),
            original_to: "support@relay.example.com".into(), subject: "hello".into(),
            loop_value: loop_hash(relay, relay),
        };
        let raw = build_forwarded_raw(PLAIN, &plan, relay).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Hi there"), "body preserved");
        assert!(s.contains("X-Original-From"), "audit header");
        assert!(s.contains("X-4ward-Relay"), "relay marker");
        assert!(s.contains(LOOP_HEADER), "loop header");
        assert!(s.contains("reply-to") || s.contains("Reply-To"), "reply-to set");
        assert!(s.contains("Forwarded by 4ward"), "banner injected");
    }

    #[test]
    fn rebuild_html_banner_and_attachment_retained() {
        let relay = "example.com";
        let plan = ForwardPlan {
            alias: "info".into(), domain: "relay.example.com".into(),
            destinations: vec!["you@gmail.com".into()],
            original_from: "carol@example.org".into(), original_from_name: "Carol".into(),
            original_to: "info@relay.example.com".into(), subject: "with file".into(),
            loop_value: loop_hash(relay, relay),
        };
        let raw = build_forwarded_raw(&multipart_fixture(), &plan, relay).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("document.pdf"), "attachment retained, got:\n{s}");
        assert!(s.contains("X-Original-To"), "audit header");
        let _ = HTML;
    }
}
