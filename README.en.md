# AI-Scan-Interceptor

**A self-hostable, open-source DLP gateway that observes and controls prompts sent from your corporate network to external AI services.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)
[![Status](https://img.shields.io/badge/Status-Beta-orange.svg)]()

English | [日本語 README](./README.md)

![AI-Scan-Interceptor demo](./assets/demo.svg)

---

## Why AI-Scan-Interceptor

Generative AI services such as ChatGPT, Claude, and Gemini have become a routine part of corporate workflows. At the same time, **employees regularly paste customer data, source code, contracts, and personal information into prompts sent to external AI providers**, and such incidents are no longer rare.

Most existing DLP and proxy products that address this are cloud-only, opaque, expensive, and impossible to audit in-house.

**AI-Scan-Interceptor is an open-source DLP purpose-built for generative AI, designed to be deployed inside your own network with a single `docker compose up` and to keep its detection logic fully inspectable.**

---

## Key Features

- **AI-aware prompt extraction**  
  Accurately extracts user-typed prompts from ChatGPT / Claude / Gemini requests.
- **Anthropic direct interception (uTLS)**  
  HTTP/2 + uTLS fingerprinting support, so Claude API traffic is not missed.
- **ICAP (RFC 3507) policy engine**  
  A generic flow combined with Squid. Regex, keyword, and classifier rules are described in YAML.
- **Endpoint agent (ai-scan-connect)**  
  Distributes proxy settings and CA certificates to Windows / macOS / Linux. mTLS keeps remote users protected too.
- **Web dashboard**  
  Real-time prompt logs, per-user usage stats, and policy-violation alerts.
- **Slack / Webhook / SMTP notifications**  
  Notify administrators the moment a policy fires.
- **Fully self-hosted**  
  Zero dependency on external SaaS. Prompt contents never leave your infrastructure.

---

## Architecture

```
[Endpoint] (Windows / macOS / Linux)
    │  HTTPS_PROXY=ai-scan-connect:port
    ▼
┌─────────────────────────────────────────────┐
│  ai-scan-connect (CA delivery + mTLS client)│
└─────────────────────────────────────────────┘
    │  mTLS
    ▼
┌─────────────────────────────────────────────┐
│  tls-proxy :3128 (Go + uTLS)                │
│    ├─ Anthropic Claude  → direct extract    │
│    └─ Others (OpenAI etc.)                  │
└─────────────────────────────────────────────┘
                                  │
                                  ▼
              ┌────────────────────────────────┐
              │  squid :3129 (TLS Bump)         │
              └────────────────────────────────┘
                                  │  ICAP REQMOD
                                  ▼
              ┌────────────────────────────────┐
              │  icap-server :1344 (Go)         │
              │    - prompt extraction          │
              │    - policy evaluation          │
              │    - logging / alerting         │
              └────────────────────────────────┘
                                  │
                                  ▼
                        ┌──────────────────┐
                        │  webui :8080      │
                        │  (dashboard)      │
                        └──────────────────┘
```

---

## Quick Start

### Requirements

- Docker Engine 24+ / Docker Compose v2
- Linux or WSL2 (also tested on macOS / Windows)
- Ports 8080 / 3128 / 3129 / 1344 available

### 1. Clone & Build

```bash
git clone https://github.com/mshirakawa-ssp/ai-scan-interceptor.git
cd ai-scan-interceptor
make certs       # generate CA certificate (first run only)
docker compose up -d --build
```

### 2. Open the dashboard

```
http://localhost:8080
```

The default admin account is `admin / admin` (please change it after first login).

### 3. Connect an endpoint

In your browser or OS network settings:

```
HTTPS Proxy: 127.0.0.1:3128
```

Import `certs/squid-ca.pem` into your OS / browser trust store.

### 4. Try it

Open Claude, ChatGPT or Gemini in your browser and ask anything. The prompt appears in the dashboard.

---

## Detection Example

Sample log entry shown on the dashboard:

```json
{
  "timestamp": "2026-05-19T10:23:41+09:00",
  "user": "alice@example.com",
  "service": "claude.ai",
  "policy_hit": "credit_card_number",
  "severity": "high",
  "action": "logged",
  "prompt_preview": "Please test a payment with card number 4111-****-****-1111..."
}
```

Policies are defined in `config/policies.yaml`:

```yaml
policies:
  - name: credit_card_number
    pattern: '\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b'
    severity: high
    action: alert
  - name: company_confidential
    keywords: ["Confidential", "Internal Only", "社外秘"]
    severity: medium
    action: log
```

---

## License

The source code in this repository is released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](./LICENSE) for the full text.

AGPL is a strong copyleft license that extends source-disclosure obligations to networked services. **Internal use and self-hosted use carry no additional restrictions.**

### Enterprise / Commercial License

A commercial license may be a better fit if you need:

- To avoid AGPL disclosure obligations in SaaS or embedded usage
- Commercial support, SLAs, or priority patches
- A managed service deployment
- Audit-ready documentation or operational outsourcing

Contact us: [secscanpro.com](https://www.secscanpro.com) / sales@secscanpro.com

---

## Contributing

Bug reports, feature proposals, documentation improvements, and pull requests are all welcome.  
Please read [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) first.

Security vulnerability disclosures: please follow [SECURITY.md](./SECURITY.md).

---

## Support the Project

If this project has been useful to you, or simply looks interesting, please consider starring it on GitHub. Stars are by far the strongest signal for us to keep investing in this project.

If you can share deployment experiences, operational tips, or war stories in Issues or Discussions, that becomes part of the shared knowledge of the community.

---

## About

AI-Scan-Interceptor is an open-source project led by **SecScanPro LLC**.

- Web: [secscanpro.com](https://www.secscanpro.com)
- HQ: Chuo, Tokyo, Japan
- Founder: Makoto Shirakawa
