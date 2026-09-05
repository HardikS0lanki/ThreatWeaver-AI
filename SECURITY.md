# Security policy

## Reporting vulnerabilities

Do not disclose suspected vulnerabilities through public issues. Contact the repository owner privately through the security-reporting mechanism configured on GitHub.

## Data-handling boundary

ThreatWeaver AI may process sensitive architecture information. Operators are responsible for authorization, data classification, retention, regional processing, model-provider terms, and connector configuration.

Never commit:

- Jira, Confluence, GitHub, cloud, or model-provider credentials;
- private tenant URLs, session cookies, exported tickets, or proprietary diagrams;
- generated assessments containing employer, customer, personal, or regulated data.

Retrieved content is untrusted and may contain prompt injection. External connectors should expose read-only, least-privilege tools. Consequential writes require explicit human authorization and review.

## Supported versions

Until a stable release is published, security fixes are provided only on the default branch.
