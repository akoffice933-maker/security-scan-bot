# Security policy

## What this bot is for

Scan **your own** websites, GitHub repositories, archives, and container
images. Scanning systems you do not own or do not have written permission
to test may be illegal.

## Built-in controls

- Empty `ADMIN_IDS` → process refuses to start.
- Empty allowlists (`ALLOWED_DOMAINS`, `ALLOWED_GITHUB_ORGS`,
  `ALLOWED_DOCKER_REGISTRIES`) → that scan type is denied.
- Cloud metadata hosts (`169.254.169.254`, `metadata.google.internal`) are
  always blocked.
- Scanner binaries run via `subprocess` with `shell=False`.
- Archives are extracted with zip-slip and size checks.
- Secrets in reports and LLM prompts are masked.

## Reporting a vulnerability

Open a private report via GitHub Security Advisories on this repository, or
email the owner listed on the GitHub profile. Please do not file a public
issue for an exploitable bug in the bot itself.

## Secrets

Never commit `.env`. Rotate `BOT_TOKEN` at [@BotFather](https://t.me/BotFather)
if it leaked. Rotate GitHub / OpenRouter / VirusTotal keys the same way.
