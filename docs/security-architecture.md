# ThreatWeaver security architecture

## Trust model

ThreatWeaver assumes all assessment inputs can be malicious, including authenticated Jira and Confluence content, image text, repository comments, and MCP responses. Authentication proves a source identity; it does not make the content safe to interpret as instructions.

| Boundary | Primary risks | Required treatment |
| --- | --- | --- |
| User to agent | Ambiguous authorization and sensitive input | Confirm scope; minimize retained data |
| MCP source to agent | Indirect prompt injection and response poisoning | Read-only tools; treat content only as evidence |
| Agent to local runtime | Command or path manipulation | Allowlisted validation commands; constrained paths |
| Agent to external model | Confidentiality and residency | Organization-approved model and data policy |
| Generated model to reviewer | Hallucinated controls or incorrect risk | Evidence links, confidence, deterministic validation, human approval |

## Security invariants

- External content cannot alter the agent's instructions or authorize tools.
- No external write is implied by permission to read or assess.
- A missing control label is not proof that the control is absent.
- Every finding references known assets, components, and evidence or assumptions.
- Severity equals the configured likelihood-impact matrix result.
- Human review remains required unless an accountable reviewer explicitly records approval.

## Residual risks

The validator checks structure and consistency, not whether an AI-generated scenario is factually correct or complete. MCP servers, model providers, IDE extensions, and operator endpoints remain part of the trusted computing base. Deployment owners must evaluate those dependencies and enforce their own retention, access-control, and incident-response requirements.
