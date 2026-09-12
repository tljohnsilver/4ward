use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};
use mail_builder::MessageBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize, Clone)]
pub struct AttachmentIn {
    pub filename: String,
    pub content: String, // base64
    #[serde(default = "default_ctype")]
    pub content_type: String,
}

fn default_ctype() -> String {
    "application/octet-stream".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct SendRequest {
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentIn>,
}

#[derive(Debug, Serialize)]
pub struct SendResponse {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
struct ErrBody {
    error: String,
}

// 60s in-memory SSM token cache: name -> (value, fetched_at)
static TOKEN_CACHE: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
fn cache() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    TOKEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn bearer_token(auth: Option<&str>) -> Option<String> {
    let h = auth?;
    let h = h.trim();
    let tok = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer "))?;
    let tok = tok.trim();
    if tok.is_empty() {
        None
    } else {
        Some(tok.to_string())
    }
}

pub fn from_domain(from: &str) -> Option<String> {
    let addr = if let Some(a) = from.rfind('<') {
        from[a + 1..].trim_end_matches('>').trim().to_string()
    } else {
        from.trim().to_string()
    };
    addr.split_once('@').map(|(_, d)| d.trim().to_lowercase())
}

pub fn allowed_domains() -> Vec<String> {
    std::env::var("ALLOWED_DOMAINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn validate_payload(req: &SendRequest) -> Result<(), String> {
    if req.to.is_empty() {
        return Err("to must contain at least one recipient".into());
    }
    if req.subject.trim().is_empty() {
        return Err("subject is required".into());
    }
    if req.html.is_none() && req.text.is_none() {
        return Err("html or text is required".into());
    }
    let dom = from_domain(&req.from).ok_or("invalid from address")?;
    let allowed = allowed_domains();
    if !allowed.is_empty() && !allowed.iter().any(|d| d == &dom) {
        return Err(format!("from domain '{dom}' is not a verified identity"));
    }
    for a in &req.attachments {
        if a.filename.trim().is_empty() {
            return Err("attachment filename is required".into());
        }
        if B64.decode(a.content.trim()).is_err() {
            return Err(format!("attachment '{}' is not valid base64", a.filename));
        }
    }
    Ok(())
}

/// Build raw MIME for SESv2 SendEmail(Raw).
pub fn build_raw(req: &SendRequest) -> Result<Vec<u8>, String> {
    let mut b = MessageBuilder::new()
        .from(req.from.as_str())
        .to(req.to.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .subject(req.subject.as_str());
    if !req.cc.is_empty() {
        b = b.cc(req.cc.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    }
    if !req.bcc.is_empty() {
        b = b.bcc(req.bcc.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    }
    if let Some(r) = req.reply_to.as_deref() {
        b = b.reply_to(r);
    }
    if let Some(t) = req.text.as_deref() {
        b = b.text_body(t);
    }
    if let Some(h) = req.html.as_deref() {
        b = b.html_body(h);
    }
    if req.text.is_none() && req.html.is_none() {
        b = b.text_body("");
    }
    let mut decoded: Vec<(String, String, Vec<u8>)> = Vec::with_capacity(req.attachments.len());
    for a in &req.attachments {
        decoded.push((
            a.content_type.clone(),
            a.filename.clone(),
            B64.decode(a.content.trim()).map_err(|e| e.to_string())?,
        ));
    }
    for (ctype, fname, bytes) in &decoded {
        b = b.attachment(ctype.as_str(), fname.as_str(), bytes.as_slice());
    }
    b.write_to_vec().map_err(|e| e.to_string())
}

async fn ssm_get(name: &str) -> Result<Option<String>, String> {
    // Cache hit (60s TTL).
    if let Ok(map) = cache().lock() {
        if let Some((v, t)) = map.get(name) {
            if t.elapsed() < Duration::from_secs(60) {
                return Ok(Some(v.clone()));
            }
        }
    }
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_ssm::Client::new(&config);
    let prefix = std::env::var("API_KEYS_PREFIX").unwrap_or("/4ward/api-keys/".into());
    // `name` here is the full token id suffix; we list keys and compare values.
    // Tokens are stored as SecureString values; lookup by listing parameters under prefix.
    let mut next: Option<String> = None;
    loop {
        let mut req = client.describe_parameters().parameter_filters(
            aws_sdk_ssm::types::ParameterStringFilter::builder()
                .key("Name")
                .option("BeginsWith")
                .values(&prefix)
                .build()
                .map_err(|e| e.to_string())?,
        );
        if let Some(t) = next {
            req = req.next_token(t);
        }
        let out = req.send().await.map_err(|e| e.to_string())?;
        let names: Vec<String> = out.parameters().iter().filter_map(|p| p.name().map(|s| s.to_string())).collect();
        for n in names {
            let v = client.get_parameter().name(&n).with_decryption(true).send().await;
            if let Ok(v) = v {
                if let Some(val) = v.parameter().and_then(|p| p.value()) {
                    if val == name {
                        if let Ok(mut map) = cache().lock() {
                            map.insert(name.to_string(), (n.clone(), Instant::now()));
                        }
                        return Ok(Some(n));
                    }
                }
            }
        }
        next = out.next_token().map(|s| s.to_string());
        if next.is_none() {
            break;
        }
    }
    Ok(None)
}

async fn verify_bearer(token: &str) -> Result<bool, String> {
    // Cache hit means previously validated.
    if let Ok(map) = cache().lock() {
        if let Some((_, t)) = map.get(token) {
            if t.elapsed() < Duration::from_secs(60) {
                return Ok(true);
            }
        }
    }
    Ok(ssm_get(token).await?.is_some())
}

fn json_resp(status: u16, body: impl Serialize) -> Result<Response<Body>, Error> {
    let s = serde_json::to_string(&body).unwrap_or("{}".into());
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(s))
        .unwrap())
}

async fn handler(event: Request) -> Result<Response<Body>, Error> {
    // Only POST /v1/emails
    let path = event.raw_http_path().to_string();
    if event.method() != "POST" || !path.ends_with("/v1/emails") {
        return json_resp(404, ErrBody { error: "not found".into() });
    }
    let auth = event.headers().get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let token = bearer_token(auth.as_deref());
    let token = match token {
        None => return json_resp(401, ErrBody { error: "missing bearer token".into() }),
        Some(t) => t,
    };
    if !token.starts_with("4w_live_") {
        return json_resp(401, ErrBody { error: "invalid token".into() });
    }
    match verify_bearer(&token).await {
        Ok(true) => {},
        Ok(false) => return json_resp(401, ErrBody { error: "invalid token".into() }),
        Err(e) => {
            tracing::warn!(error = %e, "ssm verify failed");
            return json_resp(500, ErrBody { error: "auth backend error".into() });
        }
    }
    let body = match event.body() {
        Body::Text(s) => s.as_bytes().to_vec(),
        Body::Binary(b) => b.clone(),
        Body::Empty => Vec::new(),
    };
    let req: SendRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return json_resp(400, ErrBody { error: format!("invalid payload: {e}") }),
    };
    if let Err(e) = validate_payload(&req) {
        return json_resp(400, ErrBody { error: e });
    }
    let raw = match build_raw(&req) {
        Ok(r) => r,
        Err(e) => return json_resp(400, ErrBody { error: e }),
    };
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ses = aws_sdk_sesv2::Client::new(&config);
    let from_addr = if let Some(a) = req.from.rfind('<') {
        req.from[a + 1..].trim_end_matches('>').trim().to_string()
    } else {
        req.from.trim().to_string()
    };
    let mut to_all = req.to.clone();
    to_all.extend(req.cc.clone());
    to_all.extend(req.bcc.clone());
    let config_set = std::env::var("CONFIG_SET").ok().filter(|s| !s.trim().is_empty());
    let out = ses
        .send_email()
        .from_email_address(&from_addr)
        .set_configuration_set_name(config_set)
        .set_destination(Some(
            aws_sdk_sesv2::types::Destination::builder()
                .set_to_addresses(Some(to_all))
                .build(),
        ))
        .content(
            aws_sdk_sesv2::types::EmailContent::builder()
                .raw(aws_sdk_sesv2::types::RawMessage::builder().data(aws_sdk_sesv2::primitives::Blob::new(raw)).build().map_err(|e| format!("{e:?}"))?)
                .build(),
        )
        .send()
        .await;
    match out {
        Ok(o) => json_resp(200, SendResponse { id: o.message_id().unwrap_or("").to_string(), status: "sent".into() }),
        Err(e) => {
            tracing::warn!(error = %e, "ses send failed");
            json_resp(502, ErrBody { error: "ses send failed".into() })
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    run(service_fn(handler)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer_token(Some("Bearer 4w_live_abc")).as_deref(), Some("4w_live_abc"));
        assert!(bearer_token(Some("Bearer ")).is_none());
        assert!(bearer_token(None).is_none());
    }

    #[test]
    fn from_domain_parse() {
        assert_eq!(from_domain("Acme <alerts@example.com>").as_deref(), Some("example.com"));
        assert_eq!(from_domain("a@x.io").as_deref(), Some("x.io"));
    }

    #[test]
    fn payload_validation() {
        let good = SendRequest {
            from: "Acme <alerts@example.com>".into(),
            to: vec!["customer@domain.com".into()],
            cc: vec![], bcc: vec![],
            reply_to: Some("support@example.com".into()),
            subject: "System Verification".into(),
            html: Some("<p>Your code is: <strong>849201</strong></p>".into()),
            text: Some("Your code is: 849201".into()),
            attachments: vec![AttachmentIn { filename: "document.pdf".into(), content: "JVBERi0xLjQK".into(), content_type: "application/pdf".into() }],
        };
        assert!(validate_payload(&good).is_ok());
        let mut bad = good.clone();
        bad.to.clear();
        assert!(validate_payload(&bad).is_err());
        let mut bad2 = good.clone();
        bad2.attachments[0].content = "!!!not-base64!!!".into();
        assert!(validate_payload(&bad2).is_err());
    }

    #[test]
    fn raw_build_includes_attachment() {
        let req = SendRequest {
            from: "Acme <alerts@example.com>".into(),
            to: vec!["c@d.com".into()],
            cc: vec![], bcc: vec![],
            reply_to: None,
            subject: "t".into(),
            html: Some("<p>hi</p>".into()),
            text: None,
            attachments: vec![AttachmentIn { filename: "document.pdf".into(), content: "aGVsbG8=".into(), content_type: "application/pdf".into() }],
        };
        let raw = build_raw(&req).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("document.pdf"), "attachment kept:\n{s}");
    }
}
