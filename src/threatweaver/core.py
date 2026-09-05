from __future__ import annotations

import json
from pathlib import Path
from typing import Any


LEVELS = {"very-low", "low", "medium", "high", "critical"}


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
    required = {"schema_version", "system", "evidence", "assumptions", "assets", "components", "trust_boundaries", "data_flows", "threats", "open_questions", "limitations", "human_review"}
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
    del boundary_ids, flow_ids, threat_ids
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
        missing = [key for key in ("scenario", "component_refs", "asset_refs", "evidence_refs", "recommendations", "likelihood", "impact", "severity", "confidence", "rationale") if not threat.get(key)]
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

    if model["human_review"].get("status") not in {"required", "in-progress", "approved", "rejected"}:
        errors.append("human_review.status is invalid")
    return errors


def render_markdown(model: dict[str, Any]) -> str:
    lines = [f"# Threat Model: {model['system']['name']}", "", "## Executive summary", "", model["system"]["purpose"], "", f"**Scope:** {model['system']['scope']}", "", f"**Human review:** {model['human_review']['status']}", "", "## Risk summary", "", "| ID | Severity | Category | Threat | Confidence |", "| --- | --- | --- | --- | --- |"]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for threat in sorted(model["threats"], key=lambda item: (rank[item["severity"]], item["id"])):
        lines.append(f"| {threat['id']} | {threat['severity'].upper()} | {threat['category']} | {threat['title']} | {threat['confidence']} |")
    lines.extend(["", "## Findings", ""])
    for threat in sorted(model["threats"], key=lambda item: item["id"]):
        lines.extend([f"### {threat['id']} — {threat['title']}", "", f"**Scenario:** {threat['scenario']}", "", f"**Risk:** {threat['severity']} (likelihood: {threat['likelihood']}; impact: {threat['impact']}; confidence: {threat['confidence']})", "", f"**Rationale:** {threat['rationale']}", "", f"**Evidence:** {', '.join(threat['evidence_refs'])}", "", "**Recommendations:**", ""])
        lines.extend(f"- {item}" for item in threat["recommendations"])
        lines.append("")
    lines.extend(["## Open questions", ""] + [f"- {q}" for q in model["open_questions"]] + ["", "## Assumptions and limitations", ""])
    lines.extend(f"- {item['id']}: {item['statement']}" for item in model["assumptions"])
    lines.extend(f"- {item}" for item in model["limitations"])
    lines.extend(["", "---", "Generated by ThreatWeaver AI. Advisory output; human security review required.", ""])
    return "\n".join(lines)
