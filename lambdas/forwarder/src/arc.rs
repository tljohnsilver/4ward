//! Minimal first-hop ARC sealing (RFC 8617 §5) for relayed mail.
//!
//! - Only seals when the message carries **no** incoming ARC chain (the SES
//!   inbound case). Existing chains are left untouched (skip, not fail).
//! - Pure signing: no DNS, no network. Verification of upstream auth is out
//!   of scope, so `cv=none` with an all-`none` Authentication-Results.
//! - Fail-safe direction: a broken seal is ignored by receivers; the mail
//!   itself is unaffected. Callers must fail **open** (skip sealing on Err).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// Headers covered by the ARC message signature (intersected with present).
const SIGNED: &[&str] = &[
    "from",
    "to",
    "subject",
    "date",
    "message-id",
    "reply-to",
    "mime-version",
    "content-type",
];

pub fn has_arc_chain(header_section: &str) -> bool {
    header_section.lines().any(|l| {
        let name = l.split_once(':').map(|(n, _)| n.trim()).unwrap_or("");
        name.eq_ignore_ascii_case("arc-seal")
            || name.eq_ignore_ascii_case("arc-message-signature")
            || name.eq_ignore_ascii_case("arc-authentication-results")
    })
}

fn compress_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2): lowercase name,
/// compress WSP, drop trailing WSP. `line` must be a single unfolded header.
fn relaxed_header(line: &str) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    let body = compress_ws(value).trim_end().to_string();
    // Drop leading WSP too: canonical "name:value" form.
    let body = body.trim_start().to_string();
    Some(format!("{}:{body}", name.trim().to_lowercase()))
}

/// Relaxed body canonicalization (RFC 6376 §3.4.3).
fn relaxed_body(body: &str) -> String {
    let lines: Vec<&str> = body.split('\n').collect();
    let mut end = lines.len();
    while end > 0 && lines[end - 1].trim_end_matches([' ', '\t', '\r']).is_empty() {
        end -= 1;
    }
    lines[..end]
        .iter()
        .map(|l| l.trim_end_matches([' ', '\t', '\r']))
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn split_headers_body(message: &str) -> (String, String) {
    let norm = message.replace("\r\n", "\n").replace('\r', "\n");
    match norm.split_once("\n\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (norm, String::new()),
    }
}

/// Unfold continuation lines, preserving order. Returns (lower_name, full_line).
fn unfolded_headers(header_section: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in header_section.lines() {
        if line.starts_with([' ', '\t']) && !cur.is_empty() {
            cur.push(' ');
            cur.push_str(line.trim());
        } else {
            if !cur.is_empty() {
                let name = cur.split_once(':').map(|(n, _)| n.trim().to_lowercase()).unwrap_or_default();
                out.push((name, cur.clone()));
            }
            cur = line.to_string();
        }
    }
    if !cur.is_empty() {
        let name = cur.split_once(':').map(|(n, _)| n.trim().to_lowercase()).unwrap_or_default();
        out.push((name, cur));
    }
    out
}

fn fold_b64(prefix: &str, b64: &str) -> String {
    // Fold long base64 across continuation lines (unfolds losslessly).
    let mut s = String::from(prefix);
    for (i, chunk) in b64.as_bytes().chunks(64).enumerate() {
        if i > 0 {
            s.push_str("\r\n ");
        }
        s.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    s
}

fn parse_rsa(pem: &str) -> Result<RsaPrivateKey, String> {
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| format!("pkcs1 parse: {e}"))
    } else {
        use rsa::pkcs8::DecodePrivateKey;
        RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| format!("pkcs8 parse: {e}"))
    }
}

/// Seal a fully-built relayed message. Returns the ARC header block
/// (trailing CRLF included) to **prepend** to `message`.
pub fn seal_first_hop(
    message: &[u8],
    authserv_id: &str,
    seal_domain: &str,
    selector: &str,
    private_pem: &str,
    now_unix: u64,
) -> Result<String, String> {
    if selector.trim().is_empty() || seal_domain.trim().is_empty() {
        return Err("selector/domain required".into());
    }
    let text = String::from_utf8_lossy(message);
    let (headers, body) = split_headers_body(&text);
    if has_arc_chain(&headers) {
        return Err("incoming ARC chain present; only first-hop sealing supported".into());
    }
    let hdrs = unfolded_headers(&headers);
    if !hdrs.iter().any(|(n, _)| n == "from") {
        return Err("no From header to seal".into());
    }
    let cover: Vec<String> = SIGNED
        .iter()
        .filter(|n| hdrs.iter().any(|(h, _)| h == **n))
        .map(|s| s.to_string())
        .collect();
    let h_tag = cover.join(":");

    let bh = B64.encode(Sha256::digest(relaxed_body(&body)));

    let aar = format!(
        "ARC-Authentication-Results: i=1; {authserv_id}; spf=none; dkim=none; dmarc=none"
    );
    let ams_unsigned = format!(
        "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d={seal_domain}; s={selector}; t={now_unix}; h={h_tag}; bh={bh}; b="
    );

    let key = parse_rsa(private_pem)?;
    let signer = SigningKey::<Sha256>::new(key);

    // AMS signs covered headers + itself (b= empty).
    let mut ams_input = Vec::new();
    for name in &cover {
        let line = hdrs.iter().rev().find(|(h, _)| h == name).and_then(|(_, l)| relaxed_header(l)).ok_or("header vanished")?;
        ams_input.extend_from_slice(line.as_bytes());
        ams_input.extend_from_slice(b"\r\n");
    }
    let ams_relaxed = relaxed_header(&ams_unsigned).ok_or("ams malformed")?;
    ams_input.extend_from_slice(ams_relaxed.as_bytes());
    ams_input.extend_from_slice(b"\r\n");
    let ams_sig = signer.sign(&Sha256::digest(&ams_input));
    let ams_full = fold_b64(&ams_unsigned, &B64.encode(ams_sig.to_vec()));

    // Seal signs seal(empty) + AMS + AAR, in that order.
    let seal_unsigned = format!(
        "ARC-Seal: i=1; a=rsa-sha256; cv=none; d={seal_domain}; s={selector}; t={now_unix}; b="
    );
    let mut seal_input = Vec::new();
    for h in [&seal_unsigned, &ams_full, &aar] {
        let r = relaxed_header(&h.replace("\r\n ", " ")).ok_or("seal input malformed")?;
        seal_input.extend_from_slice(r.as_bytes());
        seal_input.extend_from_slice(b"\r\n");
    }
    let seal_sig = signer.sign(&Sha256::digest(&seal_input));
    let seal_full = fold_b64(&seal_unsigned, &B64.encode(seal_sig.to_vec()));

    Ok(format!("{seal_full}\r\n{ams_full}\r\n{aar}\r\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;

    fn test_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap()
    }

    fn pem(key: &RsaPrivateKey) -> String {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap().to_string()
    }

    const MSG: &str = "From: Alice <alice@example.org>\r\nTo: you@gmail.com\r\nSubject: hi\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nHello\r\n";

    #[test]
    fn seals_and_verifies() {
        let key = test_key();
        let block = seal_first_hop(MSG.as_bytes(), "relay.example.com", "example.com", "fw1", &pem(&key), 1767225600).unwrap();
        assert!(block.contains("ARC-Seal: i=1"), "seal header:\n{block}");
        assert!(block.contains("ARC-Message-Signature: i=1"), "ams header");
        assert!(block.contains("ARC-Authentication-Results: i=1"), "aar header");
        assert!(block.contains("cv=none"), "first hop cv");

        // Independently verify the AMS signature over the same inputs.
        let unfolded_block = block.replace("\r\n ", " ");
        let ams = unfolded_block.lines().find(|l| l.starts_with("ARC-Message-Signature:")).unwrap();
        let b_pos = ams.find("; b=").unwrap();
        let ams_empty = format!("{}; b=", &ams[..b_pos]);
        let (headers, _) = split_headers_body(MSG);
        let hdrs = unfolded_headers(&headers);
        let mut input = Vec::new();
        for n in ["from", "to", "subject", "date", "content-type"] {
            let l = hdrs.iter().rev().find(|(h, _)| h == n).and_then(|(_, l)| relaxed_header(l)).unwrap();
            input.extend_from_slice(l.as_bytes());
            input.extend_from_slice(b"\r\n");
        }
        input.extend_from_slice(relaxed_header(&ams_empty).unwrap().as_bytes());
        input.extend_from_slice(b"\r\n");
        let sig_b64: String = ams[b_pos + 4..].split_whitespace().collect();
        let sig = rsa::pkcs1v15::Signature::try_from(B64.decode(sig_b64).unwrap().as_slice()).unwrap();
        VerifyingKey::<Sha256>::new(key.to_public_key()).verify(&Sha256::digest(&input), &sig).unwrap();
    }

    #[test]
    fn skips_existing_chain() {
        let chained = format!("ARC-Seal: i=1; cv=none; b=abc\r\n{MSG}");
        let key = test_key();
        assert!(seal_first_hop(chained.as_bytes(), "r", "d", "s", &pem(&key), 0).is_err());
    }

    #[test]
    fn rejects_bad_key() {
        assert!(seal_first_hop(MSG.as_bytes(), "r", "d", "s", "not-a-key", 0).is_err());
    }
}
