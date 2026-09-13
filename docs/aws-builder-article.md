# Weekend Deployment Challenge: 4ward - Zero-Cost Serverless Email Forwarding in Rust

Tags: #deployment #AWS #Serverless #Rust #Graviton

## What Your App Does

This is my entry for the AWS Builder Center Weekend Challenge: Deploy your first app on AWS. It's called **4ward**, and it exists because every side project hits the same wall a few weeks in. You register a domain, and suddenly you need two things that have nothing to do with your actual product:

1. **Inbound email** — `support@yourdomain.com` has to reach the Gmail or Outlook inbox you actually read, without breaking SPF/DMARC (a naive forward gets rejected or spam-foldered by the big providers).
2. **Outbound email** — verification codes, password resets, notifications. The "transactional API" every app needs on day one.

The path of least resistance is a hosted SaaS: a forwarding service plus an email API, bundled into a friendly monthly subscription. It works. It also means a recurring bill before your project has a single user, your mail flowing through a third party's servers, and your API keys living in someone else's database. For a pre-revenue project, that inversion — fixed cost before any value — is exactly backwards. A representative example: a $6/month forwarder is $72/year, before your project has earned anything at all.

So I built **4ward**: the same two capabilities, deployed into *your own* AWS account with two commands, costing **$0/month at idle**. It is a Rust CLI that provisions a fully serverless stack: SES inbound receiving, two Rust Lambda functions on Graviton (arm64), API Gateway, S3, and SESv2 for sending.

- **Forwarding**: your domain's aliases (individual routes or a catch-all) are delivered into your personal Gmail/Outlook inbox, rewritten so the forwarding hop passes SPF/DMARC alignment, with `Reply-To` preserving the original sender.
- **Transactional API**: from a developer's perspective, it is one HTTP endpoint — `POST /v1/emails` — authenticated with a bearer key (`Authorization: Bearer 4w_live_…`), which validates that the `from` domain is a SES-verified identity in *your* account and hands the message to SESv2 for delivery. No vendor SDK, no dashboard, no database: `curl` is a complete client.

## How You Built It

The app is a Rust workspace: the CLI (`crates/4ward-cli`, package `fourward-cli`, which builds the `4ward` binary), the shared config schema and domain logic (`crates/4ward-core`), and the two Lambda functions (`lambdas/forwarder`, `lambdas/api`). These are the decisions that shaped it.

### Why Rust on Graviton (arm64)

Two of the reasons are about the machine itself; the third — the cost model — is broken down in the next section.

**1. Graviton is the cheaper instruction set.** AWS states that Lambda functions on Graviton2 deliver up to 19% better performance at 20% lower cost than x86 — duration charges are 20% lower for arm64. Since this workload is pure CPU-bound string and crypto work (MIME parsing, RSA signing for ARC), a natively compiled binary is exactly what arm64 wants. There is no interpreter to warm up.

**2. Rust keeps the runtime small and the cold start boring.** The functions are static native binaries on `provided.al2023` — no runtime layer, no node_modules, no JIT. On memory and latency, I want to be precise about what is measured and what is a design target: **this repo does not ship a benchmark harness, so I am not going to quote audited numbers.** What I can say is that sub-15 ms warm invocations and memory footprints in the ~18 MB range are the *representative figures for this class of workload* — a small native binary doing parse-rewrite-send — and they are the design targets the implementation was built around. You can verify both in one minute on your own deployment: every Lambda invocation emits a `REPORT` line in CloudWatch Logs with `Duration` and `Max Memory Used`, and the AWS Lambda Power Tuning state machine will map the price/performance curve for your exact traffic. The 512 MB memory setting in the template is deliberately generous; the functions use a fraction of it.

### Raw MIME is the source of truth (no JSON re-encoding)

It is tempting to parse the email into JSON and rebuild it. Don't. The raw MIME is the source of truth: attachments survive without re-encoding (no base64 round-trips, no size surprises), the original headers stay intact for ARC and DMARC evaluation, and you keep full provenance for debugging deliverability. That is why the pipeline is S3-first: the SES S3 action stores the complete, unmodified message (up to SES's inbound size limit), and the Lambda pulls the object itself — the event payload only carries the bucket and key. The bucket keeps messages for a short TTL (24h by default, configurable via `settings.retention_days`), just enough to debug a missed forward.

### SRS-style rewriting and first-hop ARC sealing

The hardest design problem in forwarding is deliverability. Gmail and Outlook re-evaluate authentication on forwarded mail: the original `From` domain no longer lines up with the server that just handed them the message, so a naive forward fails SPF alignment and lands in spam.

4ward follows the *idea* behind classic SRS (the `SRS0=` envelope-encoding scheme) — make the forwarding hop originate from your own domain — but the implementation does **not** emit literal RFC `SRS0=` encoded envelope addresses. Instead it applies an SRS-style header rewrite: the `From` becomes `"{name} (via {alias})" <relay@yourdomain.com>` — an address on *your* domain, which is what keeps SPF and DMARC aligned for the hop that matters — while `Reply-To` preserves the original sender, so hitting reply still reaches the right person. Audit headers (`X-Original-From`, `X-Original-To`, `X-4ward-Relay`) and an optional provenance banner are added, and every message is first checked for a salted loop-detection marker (`X-4ward-Loop-Detection`) so `a@x.com → b@x.com`-style chains are dropped safely.

On top of the rewrite, the forwarder can seal the message with ARC (ARC-Message-Signature + ARC-Seal, first hop). Gmail and Outlook re-evaluate authentication on forwarded mail; an ARC seal lets them see that the original SPF/DKIM results were intact when you received it. The seal is fail-open: if signing fails, mail still flows.

### Deploy it in 2 commands

The CLI does the AWS work so you don't have to click through the console:

```bash
npx 4ward init       # questionnaire → writes validated 4ward.json
npx 4ward deploy     # session check → arm64 builds → CloudFormation stack
```

What actually happens, step by step:

1. **`init`** asks for your domain, region, alias routes (or catch-all), and whether you want the transactional API. It writes a validated `4ward.json` — the single source of truth for everything else.
2. **`deploy`** first validates your AWS session with STS (`get-caller-identity`) so you fail fast with a clear message instead of halfway through a stack update. Then it builds both Lambda functions with `cargo lambda build --arm64 --release` (if `cargo-lambda` isn't installed, it warns and ships placeholder code rather than failing), and creates one CloudFormation stack per domain from the embedded template: receipt rules, S3 bucket with TTL, the two functions, API Gateway with throttling, SSM key prefix, and the bounce/complaint alarms. Finally it pushes the freshly built function code.
3. **DNS is the one manual step**: `npx 4ward dns` *prints* the MX, SPF, three DKIM CNAMEs, and DMARC records as a copy-paste table (`--format json|bind` if you script it) for you to add to your DNS provider by hand — the tool does not create the records for you. If you don't already host your DNS, a hosted zone costs about $0.50/month (e.g., on Route 53). Once SES verifies the domain, mail starts flowing.
4. Create an API key and send your first transactional email:

```bash
npx 4ward keys create prod    # prints 4w_live_… exactly once

curl -X POST "$API/v1/emails" \
  -H "Authorization: Bearer 4w_live_<token>" \
  -H 'Content-Type: application/json' \
  -d '{"from":"Acme <alerts@example.com>","to":["you@personal.com"],
       "subject":"Hello from my own stack","text":"It works."}'
```

Two more commands you'll want in week two: `npx 4ward status` (sandbox status, sending quota, reputation) and `npx 4ward request-production` (automates the SES production-access request so you can email real users, not just verified addresses).

**Two ways to run it.** `npx 4ward` resolves a prebuilt binary for your platform and falls back to `cargo run -p fourward-cli` inside a source checkout. If you'd rather build from source yourself, `cargo build --release -p fourward-cli` produces the `4ward` binary; the Lambda functions cross-compile with `cargo lambda build --arm64 --release`, exactly what `deploy` runs.

## AWS Services Used / Architecture Overview

Everything in the stack is event-driven. There is no server to run, patch, or pay for while idle. The two halves of the system are independent: you can deploy forwarding only, or forwarding plus the transactional API.

```
                 INBOUND                                  OUTBOUND
 ┌──────┐   ┌─────┐   ┌───────────────┐   ┌─────────┐
 │  SES │──▶│ S3  │──▶│ Rust Lambda   │──▶│ mailbox │        ┌────────┐   ┌───────────────┐   ┌───────┐
 │inbound│  │raw  │   │ (arm64)       │   │Gmail/   │        │ client │──▶│ API Gateway   │──▶│ Rust  │
 └──────┘   │MIME │   │ SRS + ARC +   │   │Outlook  │        └────────┘   │ HTTP API      │   │Lambda │
            └─────┘   │ loop guard    │   └─────────┘                     │ bearer + rate │   └───┬───┘
                      └───────────────┘                                   └───────────────┘       ▼
                                                                                          ┌───────┐
                                                                                          │ SESv2 │
                                                                                          └───────┘
```

The services, and what each one does here:

- **Amazon Simple Email Service (SES)** — the inbound receipt rule set writes every incoming raw MIME message to S3, and SESv2 `SendEmail` handles all outbound mail: both forwarded messages and API emails.
- **Amazon S3** — stages the raw MIME messages as objects; a lifecycle TTL (24h by default, configurable via `settings.retention_days`) expires them automatically.
- **AWS Lambda** — two arm64 Rust functions: `lambda-forwarder` (the forwarding pipeline) and `lambda-api` (the transactional API), both on the `provided.al2023` custom runtime.
- **Amazon API Gateway** — the HTTP API front door for `POST /v1/emails`, with bearer auth and request throttling enforced at the edge, not in your function.
- **AWS Systems Manager Parameter Store** — stores API tokens as SecureStrings under the `/4ward/api-keys/` prefix; the API Lambda reads them with a 60-second in-memory cache to keep the hot path off SSM.
- **Amazon CloudWatch** — bounce and complaint alarms watch your sender reputation for you.

All of the infrastructure is defined in one CloudFormation template (`crates/4ward-cli/templates/template.yaml`, embedded into the CLI binary at compile time). Both functions are `provided.al2023` custom runtimes on `arm64` with 512 MB configured memory.

### Inbound: SES → S3 → forwarder Lambda → your mailbox

An SES receipt rule set matches every recipient on your verified domain and delivers the **raw MIME message** to an S3 bucket, which triggers `lambdas/forwarder` (package `lambda-forwarder`). The Lambda then:

1. **Fetches the raw message from S3** and runs a fast header scan for its own loop marker (`X-4ward-Loop-Detection`); if present, the message is dropped silently.
2. **Resolves the alias** — the recipient address (`support@example.com`) is looked up in the alias map that `4ward deploy` passes from your `4ward.json` routes (schema and validation live in `crates/4ward-core`).
3. **Rewrites the message with SRS-style semantics** (`From` → `"{name} (via {alias})" <relay@yourdomain.com>`, `Reply-To` → original sender, audit headers added) — the deliverability reasoning is in How You Built It.
4. **Optionally seals the message with ARC** (first hop, fail-open) so Gmail and Outlook can see the original SPF/DKIM results were intact.
5. **Sends via SESv2** to your real mailbox.

### Outbound: API Gateway → API Lambda → SESv2

`lambdas/api` (package `lambda-api`) sits behind an API Gateway HTTP API and exposes `POST /v1/emails`:

- **Auth**: `Authorization: Bearer 4w_live_…` tokens. Keys live in SSM as SecureStrings under the `/4ward/api-keys/` prefix (`npx 4ward keys create prod` stores the token as the value and prints it exactly once). The Lambda lists the parameter names under the prefix and compares the decrypted values against the presented token — no database, no lookup table — with a 60-second in-memory cache to keep the hot path off SSM. Revoking a key is `ssm delete-parameter` (or `npx 4ward keys revoke`).
- **Validation**: the `from` domain must be a verified SES identity in your account (the API rejects anything else), HTML and text bodies are both supported, and attachments ride along as base64.
- **Rate limiting**: API Gateway throttling is wired from your `4ward.json` (`api.rate_limit.requests_per_second` and `burst`) into the CloudFormation template, so abuse protection is enforced at the edge, not in your function.
- **Send**: the payload is assembled into raw MIME and sent with SESv2 `SendEmail`. The response is `{"id":"<ses-message-id>","status":"sent"}`.

The stack also ships CloudWatch alarms for bounce rate (>5%) and complaint rate (>0.1%) — the two reputation metrics that matter when you're on SES — so you find out before AWS does.

### Why the whole stack costs $0/month at idle

Lambda's free tier is *always free* (not a 12-month promo): 1M requests and 400,000 GB-seconds of compute per month, every month. A forwarding pipeline that sits idle most of the day uses a rounding error of that. SES is strictly pay-per-use — currently $0.10 per 1,000 emails under à-la-carte pricing (the newer plan-based pricing starts at $0.16 per 1,000) — so sending nothing costs nothing. That is the whole "$0/month at idle" claim: no traffic, no bill, no subscription to cancel when the project pauses. The entire stack fits inside the always-free Lambda tier at hobby volume; your only real costs above that are SES per-email pricing (a fraction of a cent per message) and, if you don't already have one, the DNS hosted zone the records live in.

Total AWS surface for your first deployment: SES, Lambda, API Gateway, S3, SSM, CloudWatch — all in one stack, all removable with `npx 4ward destroy`.

## What You Learned

**Reading email RFCs is a different kind of reading.** Building the forwarding rewrite meant actually understanding how receiving providers evaluate trust: SPF is checked against the domain in the message the receiver sees, so a forward that keeps the original `From` and arrives from a relay it never authorized is structurally broken. RFC 8617 (ARC) taught me the header chain — ARC-Message-Signature carries the original authentication results forward, ARC-Seal attests the chain wasn't tampered with — and, just as important, what a *first-hop* seal can honestly claim versus what later hops can't. I also learned to be precise about SRS vocabulary: the classic `SRS0=` scheme is an *envelope* encoding, while what 4ward implements is an SRS-style *header* rewrite (`From` → `relay@yourdomain.com`, `Reply-To` → original sender) that follows the same idea — make the forwarding hop pass SPF/DMARC alignment — without emitting literal `SRS0=` addresses.

**Compiling native arm64 custom runtimes is mostly about knowing what "custom runtime" means.** On `provided.al2023`, AWS gives you an OS and nothing else: your function is an executable named `bootstrap`, produced by `cargo lambda build --arm64 --release` for the Graviton target. There is no runtime layer to install and no JIT to warm up — a cold start is process start plus your `main()`. Reading the first `REPORT` line in CloudWatch Logs and seeing the duration and max memory land where the design targets said they should was the moment Graviton stopped being an abstract cost argument and became a number I could tune against.

**IAM least-privilege is a set of per-service puzzles, not one setting.** The SES receipt rule gets no broad write: a bucket policy scopes `s3:PutObject` to the raw MIME bucket, and the forwarder's role is scoped to `s3:GetObject` on that same bucket ARN — that's the only S3 it can read, and the stack grants no other write path there. Some actions don't accept a useful resource ARN (SESv2 send, `ssm:GetParameter`), so those statements stay on `*` and the real boundary becomes the execution role itself; deciding where ARN-scoping is meaningful and where it's ceremony was the actual lesson. One more gotcha from wiring the receipt rules: the rule delivers to S3 and the bucket notification triggers the Lambda, because a `LambdaAction` directly on the rule would invoke the function a second time with a non-S3 event.

## Link to App or Repo

- **GitHub**: https://github.com/tljohnsilver/4ward
- **npm**: https://www.npmjs.com/package/4ward

The repo contains the CLI (`crates/4ward-cli`), the shared domain logic and config schema (`crates/4ward-core`), both Lambda functions (`lambdas/forwarder`, `lambdas/api`), and the CloudFormation template they deploy.

Quick verification from a terminal:

```bash
npx 4ward --help     # command list and usage
npx 4ward status     # sandbox status, sending quota, reputation (uses your AWS session)
```

4ward is open source under **Apache-2.0**. PRs welcome — especially if you benchmark it and can replace my "representative figures" with your own measured ones.
