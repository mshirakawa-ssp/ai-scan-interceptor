# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-20

### Added

- Animated SVG demo (`assets/demo.svg`) embedded in `README.md` and
  `README.en.md`. The 28-second 4-stage loop walks through: terminal
  set-up → user right-clicks an AWS secret in the AWS Console and copies
  it → user pastes into Claude Desktop and clicks Send (input clears
  but nothing is actually sent) → admin clicks the blocked event in the
  dashboard to inspect the intercepted prompt.

## [0.1.0] - 2026-05-19

Initial public release of AI-Scan-Interceptor — an open-source, self-hostable
DLP gateway that observes and controls prompts sent from corporate networks to
external AI services.

### Added

- **TLS-Proxy** with uTLS-based Chrome JA3 fingerprint mimicry for direct
  interception of Anthropic Claude traffic.
- **ICAP server** (RFC 3507) for plug-in detection logic, designed to work
  with existing Squid deployments.
- **Web dashboard** for real-time prompt log viewing, per-user statistics, and
  policy-violation alerts.
- **ai-scan-connect** endpoint agent for cross-platform CA distribution and
  mTLS client identity (Windows / macOS / Linux / WSL).
- **Policy engine** supporting YAML-based rules (regex, keyword,
  severity, action).
- **Starter detection ruleset** under `config/policies/` covering PII,
  credentials/secrets, confidentiality keywords, and internal-resource
  patterns.
- **Slack / Webhook / SMTP notifications** on policy hits.
- **Dual licensing**: AGPL-3.0 for the open-source core, separate commercial
  license available for SaaS embedding and closed-source integration.
- GitHub Actions CI: per-component build, test, lint, docker-compose build,
  AGPL header verification, and Trivy vulnerability scan.
- `CONTRIBUTING.md` (DCO-based), `SECURITY.md`, `CODE_OF_CONDUCT.md`
  (Contributor Covenant v2.1), and Issue / PR templates.
- Bilingual `README.md` (Japanese) and `README.en.md` (English).

### Security

- All endpoint↔proxy traffic protected by mTLS.
- No external SaaS dependency; prompt contents never leave the operator's
  infrastructure.
- Test fixtures and example credentials are non-functional placeholder values.

### Notes

This is the first public release. Detection rules are intentionally
straightforward (regex + keyword). Classifier-based detection and additional
AI-service support (Mistral, Cohere, local LLM frontends) are on the roadmap.

[Unreleased]: https://github.com/mshirakawa-ssp/ai-scan-interceptor/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/mshirakawa-ssp/ai-scan-interceptor/releases/tag/v0.1.1
[0.1.0]: https://github.com/mshirakawa-ssp/ai-scan-interceptor/releases/tag/v0.1.0
