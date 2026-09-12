# 4ward

Open-source, zero-idle-cost serverless email engine for AWS, written in Rust. Distributed via `npx 4ward`.

One deployment gives you two capabilities:

1. **Inbound Alias Engine (SRS Forwarder)** — receives mail via SES Inbound, buffers raw MIME in S3 (24h lifecycle), rewrites headers with the Sender Rewriting Scheme, and re-dispatches to personal mailboxes (Gmail, Outlook, …) without failing SPF/DMARC.
2. **Outbound Transactional REST API** — `POST /v1/emails` on API Gateway HTTP API, backed by a Rust Lambda calling SESv2, with Bearer-token auth and attachment support.

## Quickstart

```bash
npx 4ward init              # interactive questionnaire → writes 4ward.json
npx 4ward deploy            # validates AWS session, builds arm64 Lambdas, deploys CloudFormation
npx 4ward dns               # DNS records (table | --format json|bind)
npx 4ward keys create prod  # Bearer token → SSM /4ward/api-keys/prod (prints once)
npx 4ward status            # sandbox mode, 24h quota, enforcement
npx 4ward request-production # automated SES production-access request
npx 4ward alias list        # hot alias routing editor (set/rm)
```

Prerequisites: AWS CLI session with deploy permissions, and `cargo-lambda` + Zig for local Lambda builds (deploy falls back to placeholder code with a warning if missing).

## `4ward.json`

```json
{
  "version": "1",
  "project": "4ward",
  "aws": { "region": "us-east-1", "profile": "default", "stack_name": "4ward-example-com" },
  "api": { "enabled": true, "cors": ["*"], "rate_limit": { "requests_per_second": 100, "burst": 200 } },
  "settings": { "banner_enabled": true, "retention_days": 1, "sender_format": "{name} (via {alias}) <relay@{domain}>" },
  "domains": [
    { "domain": "example.com", "dns_provider": "route53", "catch_all": "me@gmail.com",
      "routes": { "support": ["a@x.com", "b@x.com"] } }
  ]
}
```

`dns_provider` is `"route53"` (records managed for you) or `"external"` (deploy prints the MX/SPF/DKIM/DMARC table to copy).

## Outbound API

```bash
curl -X POST "$API/v1/emails" \
  -H "Authorization: Bearer 4w_live_<token>" -H 'Content-Type: application/json' -d '{
    "from": "Acme <alerts@example.com>",
    "to": ["customer@domain.com"],
    "reply_to": "support@example.com",
    "subject": "System Verification",
    "html": "<p>Your code is: <strong>849201</strong></p>",
    "text": "Your code is: 849201",
    "attachments": [{ "filename": "document.pdf", "content": "<base64>", "content_type": "application/pdf" }]
  }'
# → {"id":"<ses-message-id>","status":"sent"}
```

The `from` domain must be a verified SES identity. Tokens live in SSM under `/4ward/api-keys/*` (cached 60s in-Lambda).

## How forwarding works

SES Receipt Rule → S3 (`inbound/`, SSE-S3, 1-day expiry) + Forwarder Lambda (`arm64`, `provided.al2023`):

- Drops loops via `X-4ward-Loop-Detection`.
- Sets `Reply-To` to the original sender; `From` becomes `"{name} (via {alias})" <relay@{domain}>`.
- Stamps `X-Original-From`, `X-Original-To`, `X-4ward-Relay` and an optional provenance banner.
- Re-sends with `SESv2::SendEmail(Raw)`, preserving text/html bodies and attachments.

CloudWatch alarms ship for bounce rate (>5%) and complaint rate (>0.1%).

## Layout

```
crates/4ward-core   config schema (4ward.json) + DNS record generation
crates/4ward-cli    4ward binary; embeds templates/template.yaml via include_str!
lambdas/forwarder   inbound SRS forwarder
lambdas/api         outbound transactional API
bin/run.js          npx dispatcher (prebuilt binary per platform, cargo fallback)
```

## Dev

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo lambda build --arm64 --release --package lambda-forwarder
cargo lambda build --arm64 --release --package lambda-api
aws cloudformation validate-template --template-body file://crates/4ward-cli/templates/template.yaml
```

## License

See [LICENSE](LICENSE).
