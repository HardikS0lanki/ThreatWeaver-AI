from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


LEVELS = {"very-low", "low", "medium", "high", "critical"}
ASVS_CHAPTERS = {
    "V1": "Encoding and Sanitization", "V2": "Validation and Business Logic", "V3": "Web Frontend Security",
    "V4": "API and Web Service", "V5": "File Handling", "V6": "Authentication", "V7": "Session Management",
    "V8": "Authorization", "V9": "Self-contained Tokens", "V10": "OAuth and OIDC", "V11": "Cryptography",
    "V12": "Secure Communication", "V13": "Configuration", "V14": "Data Protection",
    "V15": "Secure Coding and Architecture", "V16": "Security Logging and Error Handling", "V17": "WebRTC",
}
ASVS_REF = re.compile(r"^v5\.0\.0-(?:[1-9]|1[0-7])\.\d+\.\d+$")
CAPEC_REF = re.compile(r"^CAPEC-[1-9]\d*$")
PROACTIVE_REF = re.compile(r"^C(?:[1-9]|10)$")


class ModelValidationError(ValueError):
    """Raised when a model violates ThreatWeaver invariants."""


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ModelValidationError("model root must be a JSON object")
    return value


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    policy_path = Path(path) if path else Path(__file__).parents[2] / "config" / "risk-policy.json"
    return load_json(policy_path)


def expected_severity(likelihood: str, impact: str, policy: dict[str, Any]) -> str:
    if likelihood not in LEVELS or impact not in LEVELS:
        raise ModelValidationError(f"invalid risk inputs: likelihood={likelihood}, impact={impact}")
    return str(policy["matrix"][likelihood][impact])


def _ids(items: list[dict[str, Any]], label: str, errors: list[str]) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(items):
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            errors.append(f"{label}[{index}] has no valid id")
        elif item_id in result:
            errors.append(f"duplicate {label} id: {item_id}")
        else:
            result.add(item_id)
    return result


def validate(model: dict[str, Any], policy: dict[str, Any] | None = None) -> list[str]:
    policy = policy or load_policy()
    errors: list[str] = []
    required = {"schema_version", "system", "evidence", "assumptions", "assets", "components", "trust_boundaries", "data_flows", "threats", "asvs_coverage", "open_questions", "limitations", "human_review"}
    for field in sorted(required - model.keys()):
        errors.append(f"missing root field: {field}")
    if errors:
        return errors
    if model["schema_version"] != "1.0":
        errors.append("schema_version must be 1.0")

    evidence_ids = _ids(model["evidence"], "evidence", errors)
    assumption_ids = _ids(model["assumptions"], "assumption", errors)
    asset_ids = _ids(model["assets"], "asset", errors)
    component_ids = _ids(model["components"], "component", errors)
    boundary_ids = _ids(model["trust_boundaries"], "trust_boundary", errors)
    flow_ids = _ids(model["data_flows"], "data_flow", errors)
    threat_ids = _ids(model["threats"], "threat", errors)
    del boundary_ids, flow_ids
    valid_evidence_refs = evidence_ids | assumption_ids

    for collection in ("assets", "components", "trust_boundaries", "data_flows"):
        for item in model[collection]:
            for ref in item.get("evidence_refs", []):
                if ref not in valid_evidence_refs:
                    errors.append(f"{item.get('id')} references unknown evidence/assumption {ref}")

    known_components = component_ids
    known_assets = asset_ids
    seen_fingerprints: set[tuple[Any, ...]] = set()
    for threat in model["threats"]:
        tid = threat.get("id", "unknown")
        required_values = ("scenario", "component_refs", "asset_refs", "evidence_refs", "recommendations", "likelihood", "impact", "impact_description", "severity", "status", "confidence", "rationale", "mapping_rationale")
        missing = [key for key in required_values if not threat.get(key)]
        if missing:
            errors.append(f"{tid} missing required values: {', '.join(missing)}")
            continue
        for ref in threat["component_refs"]:
            if ref not in known_components:
                errors.append(f"{tid} references unknown component {ref}")
        for ref in threat["asset_refs"]:
            if ref not in known_assets:
                errors.append(f"{tid} references unknown asset {ref}")
        for ref in threat["evidence_refs"]:
            if ref not in valid_evidence_refs:
                errors.append(f"{tid} references unknown evidence/assumption {ref}")
        try:
            calculated = expected_severity(threat["likelihood"], threat["impact"], policy)
            if threat["severity"] != calculated:
                errors.append(f"{tid} severity is {threat['severity']}; expected {calculated}")
        except (KeyError, ModelValidationError) as exc:
            errors.append(f"{tid} risk calculation failed: {exc}")
        fingerprint = (threat.get("category"), tuple(sorted(threat["component_refs"])), threat.get("title", "").lower().strip())
        if fingerprint in seen_fingerprints:
            errors.append(f"{tid} appears to duplicate another finding")
        seen_fingerprints.add(fingerprint)

        for ref in threat.get("asvs_refs", []):
            if not ASVS_REF.fullmatch(ref):
                errors.append(f"{tid} has invalid ASVS 5.0 reference {ref}")
        for ref in threat.get("proactive_controls", []):
            if not PROACTIVE_REF.fullmatch(ref):
                errors.append(f"{tid} has invalid Proactive Control reference {ref}")
        for ref in threat.get("capec_ids", []):
            if not CAPEC_REF.fullmatch(ref):
                errors.append(f"{tid} has invalid CAPEC reference {ref}")

    coverage = model["asvs_coverage"]
    seen_chapters: set[str] = set()
    for row in coverage:
        chapter = row.get("chapter")
        if chapter in seen_chapters:
            errors.append(f"duplicate ASVS coverage chapter: {chapter}")
        seen_chapters.add(chapter)
        if chapter not in ASVS_CHAPTERS:
            errors.append(f"invalid ASVS coverage chapter: {chapter}")
        elif row.get("title") != ASVS_CHAPTERS[chapter]:
            errors.append(f"{chapter} title must be {ASVS_CHAPTERS[chapter]}")
        for ref in row.get("requirement_refs", []):
            if not ASVS_REF.fullmatch(ref) or ref.split("-")[1].split(".")[0] != chapter[1:]:
                errors.append(f"{chapter} has invalid or cross-chapter ASVS reference {ref}")
        for ref in row.get("threat_refs", []):
            if ref not in threat_ids:
                errors.append(f"{chapter} references unknown threat {ref}")
    for chapter in sorted(set(ASVS_CHAPTERS) - seen_chapters, key=lambda x: int(x[1:])):
        errors.append(f"missing ASVS coverage chapter: {chapter}")

    if model["human_review"].get("status") not in {"required", "in-progress", "approved", "rejected"}:
        errors.append("human_review.status is invalid")
    return errors


def _cell(value: Any) -> str:
    if isinstance(value, list):
        value = "; ".join(str(item) for item in value) or "N/A"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(model: dict[str, Any]) -> str:
    lines = [f"# Threat Model: {model['system']['name']}", "", "## Executive summary", "", model["system"]["purpose"], "", f"**Scope:** {model['system']['scope']}", "", f"**Human review:** {model['human_review']['status']}", "", "## Threat and risk register", "", "| ID | Threat | STRIDE Category | Affected Components | Assets at Risk | Existing Security Controls | Impact | Security Recommendations | Likelihood | Severity | Status | ASVS 5.0 | OWASP Proactive | CAPEC | NIST | Evidence | Additional Details |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for threat in sorted(model["threats"], key=lambda item: (rank[item["severity"]], item["id"])):
        controls = [f"{c['description']} ({c['status']})" for c in threat['existing_controls']]
        values = [threat['id'], threat['title'], threat['category'], threat['component_refs'], threat['asset_refs'], controls, threat['impact_description'], threat['recommendations'], threat['likelihood'], threat['severity'], threat['status'], threat['asvs_refs'], threat['proactive_controls'], threat['capec_ids'], threat['nist_refs'], threat['evidence_refs'], threat['mapping_rationale']]
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(["", "## Detailed findings", ""])
    for threat in sorted(model["threats"], key=lambda item: item["id"]):
        lines.extend([f"### {threat['id']} — {threat['title']}", "", f"**Scenario:** {threat['scenario']}", "", f"**Risk:** {threat['severity']} (likelihood: {threat['likelihood']}; impact: {threat['impact']}; confidence: {threat['confidence']})", "", f"**Rationale:** {threat['rationale']}", "", f"**Evidence:** {', '.join(threat['evidence_refs'])}", "", "**Recommendations:**", ""])
        lines.extend(f"- {item}" for item in threat["recommendations"])
        lines.append("")
    lines.extend(["## OWASP ASVS 5.0 coverage", "", "| Chapter | Category | Applicability | Requirement references | Related threats | Notes |", "| --- | --- | --- | --- | --- | --- |"])
    for row in sorted(model["asvs_coverage"], key=lambda item: int(item["chapter"][1:])):
        lines.append("| " + " | ".join(_cell(row[key]) for key in ("chapter", "title", "applicability", "requirement_refs", "threat_refs", "notes")) + " |")
    lines.extend(["", "## Open questions", ""] + [f"- {q}" for q in model["open_questions"]] + ["", "## Assumptions and limitations", ""])
    lines.extend(f"- {item['id']}: {item['statement']}" for item in model["assumptions"])
    lines.extend(f"- {item}" for item in model["limitations"])
    lines.extend(["", "---", "Generated by ThreatWeaver AI. Advisory output; human security review required.", ""])
    return "\n".join(lines)
