# Application standards and attack-pattern mapping

Use four complementary layers; never treat them as interchangeable:

1. **STRIDE** discovers and classifies concrete threat scenarios.
2. **OWASP ASVS 5.0.0** verifies application-control coverage. Assess every V1–V17 chapter and record `applicable`, `not-applicable`, or `not-assessed` with evidence-based notes. Do not manufacture threats to fill a chapter.
3. **OWASP Top 10 Proactive Controls 2024** identifies preventive engineering practices for recommendations. It is a starting point, not a complete verification standard.
4. **MITRE CAPEC 3.9** enriches a finding with an applicable attack-pattern ID. Map only when the attack mechanics match and explain the mapping.

NIST CSF 2.0 and NIST SP 800-53 Rev. 5 references may be added when the control outcome or control ID is known. Framework mappings are advisory and are not evidence of compliance.

## ASVS 5.0 chapters

| Chapter | Category | Chapter | Category |
| --- | --- | --- | --- |
| V1 | Encoding and Sanitization | V10 | OAuth and OIDC |
| V2 | Validation and Business Logic | V11 | Cryptography |
| V3 | Web Frontend Security | V12 | Secure Communication |
| V4 | API and Web Service | V13 | Configuration |
| V5 | File Handling | V14 | Data Protection |
| V6 | Authentication | V15 | Secure Coding and Architecture |
| V7 | Session Management | V16 | Security Logging and Error Handling |
| V8 | Authorization | V17 | WebRTC |
| V9 | Self-contained Tokens |  |  |

Use stable ASVS identifiers in the exact form `v5.0.0-8.4.1`, not unversioned or guessed IDs. Do not copy ASVS requirement prose into the repository; cite the identifier and source.

## Required mapping behavior

- Every finding includes zero or more versioned ASVS IDs, Proactive Control IDs, CAPEC IDs, and NIST references plus a mapping rationale.
- Empty mapping arrays are valid when no accurate mapping exists.
- Every assessment includes exactly one coverage row for each ASVS chapter V1–V17.
- `not-assessed` means evidence was insufficient; it is not equivalent to pass.
- `not-applicable` requires a system-specific reason.
- A mapped requirement does not prove that the requirement is satisfied.

Primary sources: [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0), [OWASP Proactive Controls](https://top10proactive.owasp.org/), and [MITRE CAPEC](https://capec.mitre.org/data/index.html).
