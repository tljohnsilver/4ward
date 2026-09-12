//! DNS record generation for SES verification, reception and deliverability.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// e.g. "MX", "TXT", "CNAME"
    pub record_type: String,
    /// Host / name (relative `@` means apex).
    pub name: String,
    /// Record value / rdata.
    pub value: String,
    pub ttl: u32,
    pub purpose: String,
}

/// MX endpoint for SES inbound in a region.
pub fn inbound_mx(region: &str) -> String {
    format!("10 inbound-smtp.{region}.amazonaws.com")
}

/// SPF value authorizing SES for the domain.
pub fn spf_value() -> String {
    "v=spf1 include:amazonses.com ~all".to_string()
}

/// DMARC record value (reporting-only default).
pub fn dmarc_value(rua: &str) -> String {
    format!("v=DMARC1; p=none; rua=mailto:{rua}")
}

/// DKIM CNAME records issued by SES EasyDKIM (tokens resolved at deploy time).
/// `tokens` are the 3 DkimTokens returned by SES; each maps to
/// `<token>._domainkey.<domain> CNAME <token>.dkim.amazonses.com`.
pub fn dkim_cnames(domain: &str, tokens: &[String]) -> Vec<DnsRecord> {
    tokens
        .iter()
        .map(|t| DnsRecord {
            record_type: "CNAME".to_string(),
            name: format!("{t}._domainkey.{domain}"),
            value: format!("{t}.dkim.amazonses.com"),
            ttl: 300,
            purpose: "SES EasyDKIM signing".to_string(),
        })
        .collect()
}

/// Full record set for an external-DNS domain (DKIM tokens optional/placeholder).
pub fn records_for_domain(domain: &str, region: &str, dkim_tokens: &[String]) -> Vec<DnsRecord> {
    let mut out = vec![
        DnsRecord {
            record_type: "MX".to_string(),
            name: domain.to_string(),
            value: inbound_mx(region),
            ttl: 300,
            purpose: "SES inbound reception".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            name: domain.to_string(),
            value: spf_value(),
            ttl: 300,
            purpose: "SPF authorize SES".to_string(),
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            name: format!("_dmarc.{domain}"),
            value: dmarc_value(&format!("dmarc@{domain}")),
            ttl: 300,
            purpose: "DMARC policy".to_string(),
        },
    ];
    out.extend(dkim_cnames(domain, dkim_tokens));
    out
}

/// Placeholder DKIM tokens for `4ward dns` output before SES issues real ones.
pub fn placeholder_dkim_tokens() -> Vec<String> {
    vec![
        "token1".to_string(),
        "token2".to_string(),
        "token3".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mx_shape() {
        assert_eq!(
            inbound_mx("us-east-1"),
            "10 inbound-smtp.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn spf_authorizes_ses() {
        assert!(spf_value().contains("amazonses.com"));
    }

    #[test]
    fn full_set_has_mx_spf_dmarc_plus_dkim() {
        let recs = records_for_domain("example.com", "us-east-1", &placeholder_dkim_tokens());
        assert_eq!(recs.len(), 6);
        assert!(recs.iter().any(|r| r.record_type == "MX"));
        assert!(recs.iter().any(|r| r.name.starts_with("_dmarc.")));
        assert_eq!(
            recs.iter().filter(|r| r.record_type == "CNAME").count(),
            3
        );
    }
}
