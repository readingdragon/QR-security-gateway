# Security policy

## Supported versions

QR Security Gateway is not a production security service. No security update SLA is promised.

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/readingdragon/QR-security-gateway/security/advisories/new). If private reporting has not yet been enabled, open a public issue requesting a private reporting channel **without** including vulnerability details, credentials, exploit payloads, personal data or active phishing URLs.

Include the affected commit/version, Android version if relevant, the affected component, expected and observed behavior, impact, and minimal reproducible steps using synthetic or redacted data. Please do not test against other users, third-party sites or production accounts without authorization.

The maintainer will review reports on a best-effort basis, coordinate remediation and discuss disclosure. Avoid publishing sensitive details before a fix is available. Do not send API keys, private QR payloads, tokens or personal scan history.

## Security boundaries

QRSG warns about potentially risky HTTP/HTTPS URLs; it is not a browser, network filter, malware sandbox or guarantee of safety. It does not automatically open scanned URLs or follow redirects during analysis. Online reputation is optional and sends the URL excluding its fragment to Google after consent. A clean reputation lookup is not proof of legitimacy. The Android OS is assumed uncompromised; users may override warnings. Do not submit confidential links to external providers.

## Dependency and secret management

Use restricted API keys, never commit credentials, raw phishing datasets or private history exports, and rotate exposed keys immediately. Review dependency updates and CI findings before merging. The MIT software license does not override the terms of external services, including Google Safe Browsing's non-commercial-use restriction.
