# Output contract

Use `schemas/threat-model.schema.json` as the canonical structure.

Evidence claims use one of four statuses:

| Status | Meaning |
| --- | --- |
| `observed` | Directly visible in code, configuration, diagram, or retrieved record |
| `reported` | Asserted by a stakeholder or document but not independently verified |
| `inferred` | Reasonably derived and explicitly explained |
| `unverified` | Relevant but unsupported by available evidence |

Every threat links to component and asset IDs. `evidence_refs` may reference evidence IDs or assumption IDs, but must not be empty. Confidence reflects evidence quality, not impact.

Existing controls must include their verification status. Recommendations must be specific enough to assign to an engineering owner and verify through a test or configuration check.
