"""SARIF 2.1.0 serializer so ECDAT findings land in GitHub code scanning.

``to_sarif(scan_result)`` emits a single run whose driver declares one rule per
algorithm family (``ECDAT-RSA``, ``ECDAT-AES`` ...) and one result per detector
occurrence, each with a ``physicalLocation`` carrying ``artifactLocation.uri``
and ``region.startLine``.  That is what GitHub needs to render an annotation on
the exact line of code.

Levels map from our severity: critical/high -> ``error``, medium -> ``warning``,
low/none -> ``note``.  ``security-severity`` is set on every rule so the findings
sort correctly in the GitHub security tab.

Pure stdlib.  Never raises on a partially-populated artefact.
"""

from __future__ import annotations

import json
from typing import Any

try:  # normal package import
    from ._common import (
        TOOL_NAME,
        TOOL_URI,
        TOOL_VENDOR,
        TOOL_VERSION,
        artefact_key,
        artefacts_of,
        display_params,
        field,
        family_of,
        iso8601,
        name_of,
        occurrences_of,
        posix_path,
        rank_artefacts,
        relative_path,
        score_of,
        severity_of,
        severity_weight,
        slug,
        stable_id,
        threat_of,
    )
except ImportError:  # pragma: no cover - direct execution / partial tree
    from app.engine.serializers._common import (  # type: ignore[no-redef]
        TOOL_NAME,
        TOOL_URI,
        TOOL_VENDOR,
        TOOL_VERSION,
        artefact_key,
        artefacts_of,
        display_params,
        field,
        family_of,
        iso8601,
        name_of,
        occurrences_of,
        posix_path,
        rank_artefacts,
        relative_path,
        score_of,
        severity_of,
        severity_weight,
        slug,
        stable_id,
        threat_of,
    )

__all__ = ["to_sarif", "to_sarif_json", "SARIF_VERSION"]

SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "none": "note",
}

#: GitHub uses this 0-10 CVSS-like number to bucket alerts.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "none": "0.0",
}

_THREAT_TEXT = {
    "shor_broken": (
        "broken by Shor's algorithm on a cryptographically relevant quantum computer"
    ),
    "legacy_broken": "already broken by classical cryptanalysis",
    "grover_weakened": "security halved by Grover's algorithm",
    "quantum_safe": "believed quantum-safe at the configured parameters",
    "pqc": "a NIST post-quantum algorithm",
    "unknown": "of unclassified quantum risk",
}


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "note")


def _rule_id(family: Any) -> str:
    text = slug(family, "unknown").upper()
    return f"ECDAT-{text}"


def _rule_help_markdown(family: str, artefacts: list[Any]) -> str:
    worst = artefacts[0] if artefacts else None
    lines = [f"## {family} cryptographic assets", ""]
    if worst is not None:
        reason = field(worst, "threat_reason", "")
        if reason:
            lines.append(str(reason))
            lines.append("")
    recommendations: list[str] = []
    for artefact in artefacts:
        rec = str(field(artefact, "recommendation", "") or "").strip()
        if rec and rec not in recommendations:
            recommendations.append(rec)
    if recommendations:
        lines.append("### Recommended migration")
        lines.append("")
        lines.extend(f"- {rec}" for rec in recommendations[:8])
        lines.append("")
    rationales: list[str] = []
    for artefact in artefacts:
        text = str(field(artefact, "rec_rationale", "") or "").strip()
        if text and text not in rationales:
            rationales.append(text)
    if rationales:
        lines.append("### Why")
        lines.append("")
        lines.extend(f"- {text}" for text in rationales[:5])
        lines.append("")
    lines.append(
        "Prioritisation uses Mosca's inequality: if data shelf life (X) plus migration "
        "time (Y) exceeds the quantum horizon (Z), migration is already late."
    )
    return "\n".join(lines)


def _build_rules(artefacts: list[Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One rule per algorithm family, ordered by worst severity in that family."""
    by_family: dict[str, list[Any]] = {}
    for artefact in artefacts:
        family = family_of(artefact)
        by_family.setdefault(family, []).append(artefact)

    families = sorted(
        by_family,
        key=lambda fam: (
            -max((severity_weight(severity_of(a)) for a in by_family[fam]), default=0),
            fam.lower(),
        ),
    )
    rules: list[dict[str, Any]] = []
    index_by_rule: dict[str, int] = {}
    for index, family in enumerate(families):
        members = by_family[family]
        worst = max(members, key=lambda a: (severity_weight(severity_of(a)), score_of(a)))
        severity = severity_of(worst)
        rule_id = _rule_id(family)
        threat = threat_of(worst)
        rules.append(
            {
                "id": rule_id,
                "name": f"Ecdat{slug(family, 'Unknown').title().replace('-', '')}CryptoAsset",
                "shortDescription": {
                    "text": f"{family} cryptographic asset with quantum-risk exposure"
                },
                "fullDescription": {
                    "text": (
                        f"ECDAT discovered {len(members)} distinct {family} asset(s). "
                        f"The highest-risk instance is {_THREAT_TEXT.get(threat, threat)}."
                    )
                },
                "help": {
                    "text": (
                        f"{family}: review the discovered parameters and migrate to the "
                        "recommended NIST PQC or quantum-resistant replacement."
                    ),
                    "markdown": _rule_help_markdown(family, members),
                },
                "helpUri": TOOL_URI,
                "defaultConfiguration": {"level": _level_for(severity)},
                "properties": {
                    "tags": [
                        "security",
                        "cryptography",
                        "post-quantum",
                        "quantum-risk",
                        f"family/{slug(family)}",
                        f"threat/{slug(threat)}",
                    ],
                    "precision": "high",
                    "problem.severity": (
                        "error" if _level_for(severity) == "error" else "warning"
                    ),
                    "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                },
            }
        )
        index_by_rule[rule_id] = index
    return rules, index_by_rule


def _message_for(artefact: Any) -> str:
    name = name_of(artefact)
    threat = _THREAT_TEXT.get(threat_of(artefact), threat_of(artefact))
    parts = [f"{name} is {threat}."]
    reason = str(field(artefact, "threat_reason", "") or "").strip()
    if reason:
        parts.append(reason.rstrip(".") + ".")
    params = display_params(artefact)
    if params:
        parts.append(f"Parameters: {params}.")
    if field(artefact, "mosca_act_now", False):
        shortfall = field(artefact, "mosca_shortfall", None)
        tail = f" (shortfall {shortfall} years)" if shortfall not in (None, "") else ""
        parts.append(f"Mosca's inequality already holds{tail} - migrate now.")
    recommendation = str(field(artefact, "recommendation", "") or "").strip()
    if recommendation:
        parts.append(f"Recommended replacement: {recommendation}.")
    return " ".join(parts)


def _location(occurrence: Any, root: Any, use_base_id: bool) -> dict[str, Any]:
    raw = posix_path(field(occurrence, "file", "") or "")
    uri = relative_path(raw, root) or raw or "unknown"
    artifact_location: dict[str, Any] = {"uri": uri}
    is_absolute = raw.startswith("/") or (len(raw) > 2 and raw[1] == ":")
    if use_base_id and not is_absolute and "://" not in uri:
        artifact_location["uriBaseId"] = "%SRCROOT%"
    physical: dict[str, Any] = {"artifactLocation": artifact_location}

    line = field(occurrence, "line", None)
    start_line: int | None = None
    try:
        if line is not None and int(line) > 0:
            start_line = int(line)
    except (TypeError, ValueError):
        start_line = None
    if start_line is not None:
        region: dict[str, Any] = {"startLine": start_line}
        snippet = str(field(occurrence, "evidence", "") or "").strip()
        if snippet:
            region["snippet"] = {"text": snippet[:400]}
        physical["region"] = region
    return {"physicalLocation": physical}


def _results(artefacts: list[Any], root: Any, index_by_rule: dict[str, int],
             use_base_id: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for artefact in artefacts:
        family = family_of(artefact)
        rule_id = _rule_id(family)
        severity = severity_of(artefact)
        level = _level_for(severity)
        message = _message_for(artefact)
        key = artefact_key(artefact)
        for occurrence in occurrences_of(artefact):
            location = _location(occurrence, root, use_base_id)
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            line = location["physicalLocation"].get("region", {}).get("startLine", 0)
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [location],
                "partialFingerprints": {
                    # Artefact.key() omits the display name, so SHA-256 and
                    # SHA-512 share a key; include the name or their alerts
                    # would collapse onto one fingerprint in code scanning.
                    "ecdatArtefact/v1": stable_id(key, name_of(artefact), uri),
                    "ecdatOccurrence/v1": stable_id(key, name_of(artefact), uri, line,
                                                    field(occurrence, "evidence", "")),
                },
                "properties": {
                    "ecdat:asset": name_of(artefact),
                    "ecdat:family": family,
                    "ecdat:kind": str(field(artefact, "kind", "algorithm") or "algorithm"),
                    "ecdat:severity": severity,
                    "ecdat:score": score_of(artefact),
                    "ecdat:threat": threat_of(artefact),
                    "ecdat:detector": str(field(occurrence, "detector", "") or ""),
                    "ecdat:confidence": str(field(occurrence, "confidence", "") or ""),
                    "ecdat:mosca:act_now": bool(field(artefact, "mosca_act_now", False)),
                    "ecdat:mosca:shortfall_years": field(artefact, "mosca_shortfall", None),
                    "ecdat:recommendation": str(field(artefact, "recommendation", "") or ""),
                    "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                    "tags": ["cryptography", "post-quantum", f"threat/{slug(threat_of(artefact))}"],
                },
            }
            if rule_id in index_by_rule:
                result["ruleIndex"] = index_by_rule[rule_id]
            patch = str(field(artefact, "fix_patch", "") or "").strip()
            if patch:
                result["properties"]["ecdat:fix_patch"] = patch
            results.append(result)
    return results


def _artifacts_section(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for result in results:
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        uri = location["uri"]
        if uri in seen:
            continue
        entry: dict[str, Any] = {"location": dict(location)}
        entry["sourceLanguage"] = _language_for(uri)
        seen[uri] = entry
    return list(seen.values())


_EXT_LANGUAGE = {
    "py": "python", "pyi": "python", "js": "javascript", "mjs": "javascript",
    "cjs": "javascript", "jsx": "javascript", "ts": "typescript", "tsx": "typescript",
    "java": "java", "go": "go", "rb": "ruby", "php": "php", "c": "c", "h": "c",
    "cc": "cpp", "cpp": "cpp", "hpp": "cpp", "cs": "csharp", "rs": "rust",
    "kt": "kotlin", "swift": "swift", "sh": "shell", "yaml": "yaml", "yml": "yaml",
    "json": "json", "xml": "xml", "pem": "plaintext", "crt": "plaintext",
    "cer": "plaintext", "conf": "plaintext", "cnf": "plaintext",
}


def _language_for(uri: str) -> str:
    ext = uri.rsplit(".", 1)[-1].lower() if "." in uri else ""
    return _EXT_LANGUAGE.get(ext, "plaintext")


def to_sarif(scan_result: Any, *, tool_version: str = TOOL_VERSION) -> dict[str, Any]:
    """Serialize a :class:`ScanResult` as a SARIF 2.1.0 log.

    Args:
        scan_result: a ``ScanResult`` (or its ``to_dict()`` form).
        tool_version: version reported for the ECDAT driver.

    Returns:
        A JSON-serialisable ``dict`` ready for ``github/codeql-action/upload-sarif``.
    """
    target = posix_path(field(scan_result, "target", "") or "")
    artefacts = rank_artefacts(artefacts_of(scan_result))
    errors = list(field(scan_result, "errors", []) or [])

    rules, index_by_rule = _build_rules(artefacts)
    use_base_id = bool(target)
    results = _results(artefacts, target, index_by_rule, use_base_id)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "fullName": "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
                "organization": TOOL_VENDOR,
                "version": tool_version,
                "semanticVersion": tool_version,
                "informationUri": TOOL_URI,
                "rules": rules,
            }
        },
        "automationDetails": {
            "id": f"ecdat/crypto-discovery/{slug(target, 'target')}/",
            "description": {
                "text": f"ECDAT cryptographic discovery and quantum-risk analysis of {target or 'target'}"
            },
        },
        "columnKind": "utf16CodeUnits",
        "results": results,
        "properties": {
            "ecdat:files_scanned": field(scan_result, "files_scanned", 0),
            "ecdat:artefacts": len(artefacts),
            "ecdat:policy": str(field(scan_result, "policy_name", "default") or "default"),
            "ecdat:mosca:act_now": sum(
                1 for a in artefacts if field(a, "mosca_act_now", False)
            ),
        },
    }
    if use_base_id:
        run["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": _root_uri(target), "description": {"text": "Scan target root"}}
        }

    artifacts = _artifacts_section(results)
    if artifacts:
        run["artifacts"] = artifacts

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "startTimeUtc": iso8601(field(scan_result, "started", None)),
        "endTimeUtc": iso8601(field(scan_result, "finished", None)),
    }
    if errors:
        invocation["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": str(err)[:1000]}}
            for err in errors[:100]
        ]
    run["invocations"] = [invocation]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _root_uri(target: str) -> str:
    text = posix_path(target)
    if "://" in text:
        return text
    if text.startswith("/"):
        return "file://" + text.rstrip("/") + "/"
    return (text.rstrip("/") + "/") if text else "./"


def to_sarif_json(scan_result: Any, *, indent: int = 2, **kwargs: Any) -> str:
    """Convenience wrapper returning the SARIF log as a JSON string."""
    return json.dumps(to_sarif(scan_result, **kwargs), indent=indent, default=str)
