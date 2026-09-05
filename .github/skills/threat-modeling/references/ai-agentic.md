# AI and agentic assessment

In addition to STRIDE, evaluate relevant OWASP LLM risks and agent-specific attack paths.

- Instructions: direct and indirect prompt injection, instruction hierarchy, data/instruction separation, encoding and multimodal payloads.
- Retrieval: source authorization, tenant filtering before retrieval, poisoning, embedding inversion, stale permissions, citations, and deletion propagation.
- Model: provenance, version changes, extraction, memorization, unsafe output reliance, evaluation coverage, and denial-of-wallet.
- Tools and MCP: tool provenance, capability allowlists, parameter validation, confused deputy, credential delegation, response poisoning, approval gates, and audit trails.
- Agent authority: least agency, bounded goals, recursion limits, transaction limits, durable-memory poisoning, identity, and human confirmation for consequential actions.
- Orchestration: cross-agent trust, message authenticity, shared-memory isolation, termination, conflict handling, and compromised-agent containment.
- Output: context-appropriate encoding, downstream command injection, sensitive-data filtering, grounding, uncertainty, and safe failure.

Apply MAESTRO as a layered review aid for model, agent, environment, synthesis, tools, retrieval, and orchestration. Do not present MAESTRO as a risk-scoring algorithm.
