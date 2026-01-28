#!/usr/bin/env python3
"""
Azure RBAC Security Posture Analysis Engine.

Analyzes RBAC extraction data against 9 security rules based on industry
frameworks (NIST SP 800-53, Microsoft Cloud Security Benchmark, WAF Security
Pillar, CIS Azure Benchmark, OWASP Top 10).

Produces:
    - Machine-readable JSON findings
    - Human-readable HTML report
    - Human-readable Markdown report

Usage:
    python analyze_security.py output/rbac-my-rg-20260128-143000.json
    python analyze_security.py output/rbac-my-rg-20260128-143000.json --output-dir ./custom
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from constants import (
    BROAD_ROLES,
    EXCESSIVE_PRIVILEGE_THRESHOLD,
    FRAMEWORK_REFERENCES,
    GUID_PATTERN,
    OVERLY_PRIVILEGED_ROLES,
    PASSIVE_RESOURCE_TYPES,
    ROLE_RESOURCE_RULES,
    SECURITY_RULES,
    is_data_plane_role,
)


# ── Data Loading ────────────────────────────────────────────────────────────


def load_rbac_data(filepath: Path) -> dict:
    """Load and validate the RBAC extraction JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "metadata" not in data or "resources" not in data:
        print("ERROR: Invalid RBAC JSON (missing metadata or resources)", file=sys.stderr)
        sys.exit(1)
    return data


# ── Finding Builder ─────────────────────────────────────────────────────────


def build_finding(
    rule_id: str,
    resource: dict,
    assignment: dict,
    details: str,
) -> dict:
    """Construct a standardized finding dict with resolved framework refs."""
    rule = SECURITY_RULES[rule_id]
    refs = [FRAMEWORK_REFERENCES[k] for k in rule["references"]]
    return {
        "ruleId": rule["id"],
        "ruleName": rule["name"],
        "severity": rule["severity"],
        "category": rule["category"],
        "description": rule["description"],
        "recommendation": rule["recommendation"],
        "references": refs,
        "resource": {
            "name": resource.get("resourceName", ""),
            "type": resource.get("resourceType", ""),
            "id": resource.get("resourceId", ""),
        },
        "assignment": {
            "roleName": assignment.get("roleName", ""),
            "principalName": assignment.get("principalName", ""),
            "principalType": assignment.get("principalType", ""),
            "principalId": assignment.get("principalId", ""),
            "scope": assignment.get("scope", ""),
        },
        "details": details,
    }


# ── Security Rule Implementations ──────────────────────────────────────────


def check_rbac_001(rbac_data: dict) -> list[dict]:
    """RBAC-001: Overly Privileged Roles at Resource Level."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            if (
                assignment["roleName"] in OVERLY_PRIVILEGED_ROLES
                and not assignment["isInherited"]
            ):
                findings.append(build_finding(
                    "RBAC-001", resource, assignment,
                    f"'{assignment['roleName']}' assigned directly to "
                    f"'{assignment['principalName']}' on resource "
                    f"'{resource['resourceName']}'. "
                    f"Use a more specific role.",
                ))
    return findings


def check_rbac_002(rbac_data: dict) -> list[dict]:
    """RBAC-002: Individual User Assignments (not using groups)."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            if assignment["principalType"] == "User":
                findings.append(build_finding(
                    "RBAC-002", resource, assignment,
                    f"User '{assignment['principalName']}' has direct "
                    f"assignment (role: '{assignment['roleName']}'). "
                    f"Use security groups instead.",
                ))
    return findings


def check_rbac_003(rbac_data: dict) -> list[dict]:
    """RBAC-003: Role-Resource Type Mismatch."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            role = assignment["roleName"]
            if role in ROLE_RESOURCE_RULES:
                allowed = ROLE_RESOURCE_RULES[role]
                if resource["resourceType"] not in allowed:
                    findings.append(build_finding(
                        "RBAC-003", resource, assignment,
                        f"'{role}' is designed for "
                        f"{', '.join(allowed)}, not "
                        f"'{resource['resourceType']}'.",
                    ))
    return findings


def check_rbac_004(rbac_data: dict) -> list[dict]:
    """RBAC-004: Excessive High-Privilege Principals per Resource."""
    findings = []
    for resource in rbac_data.get("resources", []):
        privileged: dict[str, dict] = {}
        for assignment in resource.get("assignments", []):
            if assignment["roleName"] in ("Owner", "Contributor"):
                pid = assignment["principalId"]
                if pid not in privileged:
                    privileged[pid] = assignment

        if len(privileged) > EXCESSIVE_PRIVILEGE_THRESHOLD:
            names = ", ".join(a["principalName"] for a in privileged.values())
            first = next(iter(privileged.values()))
            findings.append(build_finding(
                "RBAC-004", resource, first,
                f"Resource '{resource['resourceName']}' has "
                f"{len(privileged)} principals with Owner/Contributor "
                f"(threshold: {EXCESSIVE_PRIVILEGE_THRESHOLD}). "
                f"Principals: {names}",
            ))
    return findings


def check_rbac_005(rbac_data: dict) -> list[dict]:
    """RBAC-005: Service Principal with Broad Roles."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            if (
                assignment["principalType"] == "ServicePrincipal"
                and assignment["roleName"] in BROAD_ROLES
            ):
                findings.append(build_finding(
                    "RBAC-005", resource, assignment,
                    f"Service principal '{assignment['principalName']}' "
                    f"has '{assignment['roleName']}' role. SPNs with "
                    f"broad roles are high-risk due to non-interactive "
                    f"authentication.",
                ))
    return findings


def check_rbac_006(rbac_data: dict) -> list[dict]:
    """RBAC-006: Orphaned/Unknown Principals."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            ptype = assignment.get("principalType", "")
            pname = assignment.get("principalName", "")
            is_orphaned = (
                ptype == "Unknown"
                or ptype == ""
                or not pname
                or GUID_PATTERN.match(pname)
            )
            if is_orphaned:
                findings.append(build_finding(
                    "RBAC-006", resource, assignment,
                    f"Principal '{assignment['principalId']}' cannot be "
                    f"resolved. The identity may have been deleted from "
                    f"Entra ID.",
                ))
    return findings


def check_rbac_007(rbac_data: dict) -> list[dict]:
    """RBAC-007: Separation of Duties Violation."""
    findings = []
    for resource in rbac_data.get("resources", []):
        principal_planes: dict[str, set[str]] = defaultdict(set)
        principal_assignments: dict[str, list[dict]] = defaultdict(list)

        for assignment in resource.get("assignments", []):
            pid = assignment["principalId"]
            principal_planes[pid].add(assignment["plane"])
            principal_assignments[pid].append(assignment)

        for pid, planes in principal_planes.items():
            if "controlPlane" in planes and "dataPlane" in planes:
                rep = principal_assignments[pid][0]
                ctrl = [
                    a["roleName"]
                    for a in principal_assignments[pid]
                    if a["plane"] == "controlPlane"
                ]
                data = [
                    a["roleName"]
                    for a in principal_assignments[pid]
                    if a["plane"] == "dataPlane"
                ]
                findings.append(build_finding(
                    "RBAC-007", resource, rep,
                    f"Principal '{rep['principalName']}' has both "
                    f"control plane ({', '.join(ctrl)}) and data plane "
                    f"({', '.join(data)}) roles on "
                    f"'{resource['resourceName']}'.",
                ))
    return findings


def check_rbac_008(rbac_data: dict) -> list[dict]:
    """RBAC-008: Assignments on Passive Infrastructure."""
    findings = []
    for resource in rbac_data.get("resources", []):
        if resource["resourceType"] in PASSIVE_RESOURCE_TYPES:
            for assignment in resource.get("assignments", []):
                findings.append(build_finding(
                    "RBAC-008", resource, assignment,
                    f"Role '{assignment['roleName']}' assigned on "
                    f"passive infrastructure resource "
                    f"'{resource['resourceName']}' "
                    f"({resource['resourceType']}).",
                ))
    return findings


def check_rbac_009(rbac_data: dict) -> list[dict]:
    """RBAC-009: Inherited Broad Permissions."""
    findings = []
    for resource in rbac_data.get("resources", []):
        for assignment in resource.get("assignments", []):
            if (
                assignment["isInherited"]
                and assignment["roleName"] in OVERLY_PRIVILEGED_ROLES
            ):
                scope = assignment["scope"]
                if "/resourceGroups/" in scope and "/providers/" not in scope.split("/resourceGroups/", 1)[-1]:
                    source = "resource group"
                elif "/subscriptions/" in scope and "/resourceGroups/" not in scope:
                    source = "subscription"
                else:
                    source = "parent scope"
                findings.append(build_finding(
                    "RBAC-009", resource, assignment,
                    f"'{assignment['roleName']}' inherited from "
                    f"{source} to '{resource['resourceName']}' for "
                    f"principal '{assignment['principalName']}'.",
                ))
    return findings


# ── Analysis Orchestrator ───────────────────────────────────────────────────

_ALL_CHECKS = [
    check_rbac_001,
    check_rbac_002,
    check_rbac_003,
    check_rbac_004,
    check_rbac_005,
    check_rbac_006,
    check_rbac_007,
    check_rbac_008,
    check_rbac_009,
]


def run_all_rules(rbac_data: dict) -> list[dict]:
    """Execute all security rules and return combined findings."""
    findings = []
    for check_fn in _ALL_CHECKS:
        findings.extend(check_fn(rbac_data))
    return findings


# ── Findings JSON Output ───────────────────────────────────────────────────


def write_findings_json(
    findings: list[dict],
    metadata: dict,
    output_path: Path,
) -> None:
    """Write findings to machine-readable JSON."""
    severity_counts: dict[str, int] = defaultdict(int)
    rule_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        severity_counts[f["severity"]] += 1
        rule_counts[f["ruleId"]] += 1

    # Collect unique frameworks cited
    seen_fw: dict[str, dict] = {}
    for f in findings:
        for ref in f["references"]:
            fw_name = ref["framework"]
            if fw_name not in seen_fw:
                seen_fw[fw_name] = {"framework": fw_name, "controls": [], "url": ref["url"]}
            ctrl = ref["id"]
            if ctrl not in seen_fw[fw_name]["controls"]:
                seen_fw[fw_name]["controls"].append(ctrl)

    output = {
        "metadata": {
            **metadata,
            "analyzedAt": datetime.now(timezone.utc).isoformat(),
            "toolVersion": "test2-1.0",
        },
        "summary": {
            "totalFindings": len(findings),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "byRule": {
                rule_id: rule_counts.get(rule_id, 0)
                for rule_id in sorted(SECURITY_RULES.keys())
            },
        },
        "findings": findings,
        "frameworksCited": list(seen_fw.values()),
    }

    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(output, fp, indent=2)


# ── HTML Report ─────────────────────────────────────────────────────────────

_CSS = """\
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0; padding: 20px; background: #f5f5f5;
}
.container { max-width: 1400px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,.1); }
h1 { color: #2a4b8d; border-bottom: 3px solid #2a4b8d; padding-bottom: 10px; }
h2 { color: #2a4b8d; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
h3 { color: #333; margin-top: 20px; }
.summary-box { background: #f0f4f8; border-left: 4px solid #2a4b8d; padding: 15px; margin: 20px 0; }
.summary-box ul { margin: 5px 0; padding-left: 20px; }
.nav-box { background: #f9f9f9; border-left: 4px solid #666; padding: 15px; margin: 20px 0; }
.nav-box ul { list-style: none; padding-left: 0; }
.sev-high { color: #d13438; font-weight: bold; }
.sev-medium { color: #ff6b00; font-weight: bold; }
.sev-low { color: #107c10; font-weight: bold; }
.badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: .85em; font-weight: bold; }
.badge-high { background: #fed5d7; color: #d13438; }
.badge-medium { background: #fff4ce; color: #ff6b00; }
.badge-low { background: #dffcf0; color: #107c10; }
.badge-control { background: #e7eef9; color: #2a4b8d; }
.badge-data { background: #f1ebe0; color: #8a4d00; }
.finding-card { border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin: 15px 0; background: #fafafa; }
.finding-card.high { border-left: 5px solid #d13438; }
.finding-card.medium { border-left: 5px solid #ff6b00; }
.finding-card.low { border-left: 5px solid #ffc83d; }
.finding-card h4 { margin-top: 0; }
.detail-item { margin: 6px 0; }
.detail-label { font-weight: bold; color: #555; }
.recommendation-box { background: #e8f5e9; border-left: 3px solid #107c10; padding: 10px; margin: 10px 0; border-radius: 3px; }
.references-box { background: #e8f0fe; border-left: 3px solid #1a73e8; padding: 10px; margin: 10px 0; border-radius: 3px; }
.ref-link { display: inline-block; margin: 2px 4px; padding: 2px 8px; background: #d2e3fc; border-radius: 3px; font-size: .85em; text-decoration: none; color: #1a73e8; }
.ref-link:hover { background: #aecbfa; text-decoration: underline; }
.scope-code { background: #f5f5f5; border: 1px solid #ddd; border-radius: 3px; padding: 3px 6px; font-family: Consolas, Monaco, monospace; font-size: .85em; word-break: break-all; }
table { border-collapse: collapse; width: 100%; margin: 20px 0; font-size: .9em; }
th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; }
th { background: #2a4b8d; color: #fff; position: sticky; top: 0; }
tr:nth-child(even) { background: #f9f9f9; }
.collapsible { border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin: 20px 0; background: #fafafa; }
.collapsible summary { cursor: pointer; font-weight: bold; padding: 5px; user-select: none; }
.collapsible summary:hover { background: #f0f0f0; border-radius: 2px; }
.collapsible summary h2 { margin: 0; padding: 0; display: inline; font-size: 1.5em; }
.collapsible[open] { background: #fff; }
.no-findings { text-align: center; padding: 40px; font-size: 1.2em; color: #107c10; }
"""


def _severity_badge(severity: str) -> str:
    cls = severity.lower()
    return f'<span class="badge badge-{cls}">{escape(severity)}</span>'


def _plane_badge(plane: str) -> str:
    if "data" in plane.lower():
        return '<span class="badge badge-data">Data Plane</span>'
    return '<span class="badge badge-control">Control Plane</span>'


def generate_html_report(
    findings: list[dict],
    rbac_data: dict,
    output_path: Path,
) -> None:
    """Generate comprehensive HTML security report."""
    h = []
    metadata = rbac_data.get("metadata", {})
    resources = rbac_data.get("resources", [])

    # -- header --
    h.append("<!DOCTYPE html>\n<html>\n<head>")
    h.append('<meta charset="utf-8">')
    h.append("<title>Azure RBAC Security Posture Report</title>")
    h.append(f"<style>{_CSS}</style>")
    h.append('</head>\n<body>\n<div class="container">')

    h.append("<h1>Azure RBAC Security Posture Report</h1>")
    h.append(f'<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')

    # -- executive summary --
    sev_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f["severity"]] += 1

    total_assignments = sum(len(r.get("assignments", [])) for r in resources)

    h.append('<div class="summary-box">')
    h.append("<h2>Executive Summary</h2>")
    h.append("<ul>")
    h.append(f'<li><strong>Subscription:</strong> {escape(metadata.get("subscriptionName", "Unknown"))} ({escape(metadata.get("subscriptionId", "Unknown"))})</li>')
    h.append(f'<li><strong>Resource Group:</strong> {escape(metadata.get("resourceGroup", "Unknown"))}</li>')
    h.append(f'<li><strong>Resources Analyzed:</strong> {metadata.get("resourceCount", 0)}</li>')
    h.append(f'<li><strong>Total Role Assignments:</strong> {total_assignments}</li>')
    h.append(f'<li><strong>Include Inherited:</strong> {"Yes" if metadata.get("includeInherited") else "No"}</li>')
    h.append(f'<li><strong>Security Findings:</strong> {len(findings)}</li>')
    h.append(f'<li class="sev-high">HIGH: {sev_counts.get("HIGH", 0)}</li>')
    h.append(f'<li class="sev-medium">MEDIUM: {sev_counts.get("MEDIUM", 0)}</li>')
    h.append(f'<li class="sev-low">LOW: {sev_counts.get("LOW", 0)}</li>')
    h.append("</ul></div>")

    # -- navigation --
    h.append('<div class="nav-box">')
    h.append("<h2>Quick Navigation</h2><ul>")
    for sev, label, emoji in [("HIGH", "High", "&#x1F534;"), ("MEDIUM", "Medium", "&#x1F7E0;"), ("LOW", "Low", "&#x1F7E1;")]:
        if sev_counts.get(sev, 0):
            h.append(f'<li>{emoji} <a href="#sev-{sev.lower()}">{label} Severity Findings</a> ({sev_counts[sev]})</li>')
    h.append('<li>&#x1F4CB; <a href="#inventory">RBAC Inventory</a></li>')
    h.append('<li>&#x1F4DA; <a href="#frameworks">Framework Reference Summary</a></li>')
    h.append('<li>&#x1F4C4; <a href="#appendix">Appendix: All Assignments</a></li>')
    h.append("</ul></div>")

    # -- findings by severity --
    if not findings:
        h.append('<div class="no-findings">No security findings detected.</div>')
    else:
        by_sev: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            by_sev[f["severity"]].append(f)

        for sev, emoji in [("HIGH", "&#x1F534;"), ("MEDIUM", "&#x1F7E0;"), ("LOW", "&#x1F7E1;")]:
            if sev not in by_sev:
                continue
            items = by_sev[sev]
            open_attr = " open" if sev == "HIGH" else ""
            h.append(f'<details class="collapsible"{open_attr}>')
            h.append(f'<summary><h2 id="sev-{sev.lower()}">{emoji} {sev} Severity ({len(items)} findings)</h2></summary>')

            # group by rule
            by_rule: dict[str, list[dict]] = defaultdict(list)
            for f in items:
                by_rule[f["ruleId"]].append(f)

            for rule_id in sorted(by_rule.keys()):
                rule_findings = by_rule[rule_id]
                rule_name = rule_findings[0]["ruleName"]
                h.append(f"<h3>{escape(rule_id)}: {escape(rule_name)} ({len(rule_findings)} findings)</h3>")
                h.append(f'<p><em>{escape(rule_findings[0]["description"])}</em></p>')

                for i, f in enumerate(rule_findings, 1):
                    cls = sev.lower()
                    h.append(f'<div class="finding-card {cls}">')
                    h.append(f"<h4>Finding {i}</h4>")
                    h.append(f'<div class="detail-item"><span class="detail-label">Resource:</span> {escape(f["resource"]["name"])} <em>({escape(f["resource"]["type"])})</em></div>')
                    h.append(f'<div class="detail-item"><span class="detail-label">Role:</span> {escape(f["assignment"]["roleName"])}</div>')
                    h.append(f'<div class="detail-item"><span class="detail-label">Principal:</span> {escape(f["assignment"]["principalName"])} ({escape(f["assignment"]["principalType"])})</div>')
                    h.append(f'<div class="detail-item"><span class="detail-label">Scope:</span> <code class="scope-code">{escape(f["assignment"]["scope"])}</code></div>')
                    h.append(f'<div class="detail-item"><span class="detail-label">Details:</span> {escape(f["details"])}</div>')

                    # recommendation
                    h.append(f'<div class="recommendation-box"><strong>Recommendation:</strong> {escape(f["recommendation"])}</div>')

                    # references
                    h.append('<div class="references-box"><strong>References:</strong><br>')
                    for ref in f["references"]:
                        label = f'{escape(ref["framework"])} {escape(ref["id"])}: {escape(ref["name"])}'
                        h.append(f'<a class="ref-link" href="{escape(ref["url"])}" target="_blank" rel="noopener">{label}</a>')
                    h.append("</div>")

                    h.append("</div>")  # finding-card

            h.append("</details>")

    # -- RBAC Inventory --
    h.append('<details class="collapsible" open>')
    h.append('<summary><h2 id="inventory">RBAC Inventory</h2></summary>')

    # by resource
    h.append("<h3>By Resource</h3>")
    for resource in sorted(resources, key=lambda r: r["resourceName"]):
        assignments = resource.get("assignments", [])
        if not assignments:
            continue
        h.append(f'<h4>{escape(resource["resourceName"])} <em style="font-size:.8em;color:#666">({escape(resource["resourceType"])})</em></h4>')
        h.append("<table>")
        h.append("<tr><th>Role</th><th>Principal</th><th>Type</th><th>Plane</th><th>Inherited</th></tr>")
        for a in assignments:
            inh = "Yes" if a["isInherited"] else "No"
            h.append(f'<tr><td>{escape(a["roleName"])}</td><td>{escape(a["principalName"])}</td><td>{escape(a["principalType"])}</td><td>{_plane_badge(a["plane"])}</td><td>{inh}</td></tr>')
        h.append("</table>")

    # by role
    h.append("<h3>By Role</h3>")
    role_map: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for resource in resources:
        for a in resource.get("assignments", []):
            role_map[a["roleName"]].append((resource, a))
    for role_name in sorted(role_map.keys()):
        entries = role_map[role_name]
        plane = "dataPlane" if is_data_plane_role(role_name) else "controlPlane"
        h.append(f"<h4>{escape(role_name)} {_plane_badge(plane)} ({len(entries)} assignments)</h4>")
        h.append("<table>")
        h.append("<tr><th>Resource</th><th>Type</th><th>Principal</th><th>Principal Type</th><th>Inherited</th></tr>")
        for res, a in entries:
            inh = "Yes" if a["isInherited"] else "No"
            h.append(f'<tr><td>{escape(res["resourceName"])}</td><td>{escape(res["resourceType"])}</td><td>{escape(a["principalName"])}</td><td>{escape(a["principalType"])}</td><td>{inh}</td></tr>')
        h.append("</table>")

    # by principal
    h.append("<h3>By Principal</h3>")
    principal_map: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for resource in resources:
        for a in resource.get("assignments", []):
            key = a["principalName"] or a["principalId"]
            principal_map[key].append((resource, a))
    for pname in sorted(principal_map.keys()):
        entries = principal_map[pname]
        ptype = entries[0][1]["principalType"]
        h.append(f"<h4>{escape(pname)} ({escape(ptype)}) - {len(entries)} assignments</h4>")
        h.append("<table>")
        h.append("<tr><th>Resource</th><th>Type</th><th>Role</th><th>Plane</th><th>Inherited</th></tr>")
        for res, a in entries:
            inh = "Yes" if a["isInherited"] else "No"
            h.append(f'<tr><td>{escape(res["resourceName"])}</td><td>{escape(res["resourceType"])}</td><td>{escape(a["roleName"])}</td><td>{_plane_badge(a["plane"])}</td><td>{inh}</td></tr>')
        h.append("</table>")

    h.append("</details>")

    # -- Framework Reference Summary --
    h.append(f'<h2 id="frameworks">Framework Reference Summary</h2>')
    fw_summary: dict[str, dict] = {}
    for f in findings:
        for ref in f["references"]:
            fw = ref["framework"]
            if fw not in fw_summary:
                fw_summary[fw] = {"controls": set(), "url": ref["url"]}
            fw_summary[fw]["controls"].add(ref["id"])
    if fw_summary:
        h.append("<table>")
        h.append("<tr><th>Framework</th><th>Controls Cited</th><th>URL</th></tr>")
        for fw_name in sorted(fw_summary.keys()):
            info = fw_summary[fw_name]
            ctrls = ", ".join(sorted(info["controls"]))
            h.append(f'<tr><td>{escape(fw_name)}</td><td>{escape(ctrls)}</td><td><a href="{escape(info["url"])}" target="_blank" rel="noopener">Link</a></td></tr>')
        h.append("</table>")
    else:
        h.append("<p>No frameworks cited (no findings).</p>")

    # -- Appendix --
    h.append(f'<h2 id="appendix">Appendix: All Assignments</h2>')
    h.append("<table>")
    h.append("<tr><th>Resource</th><th>Type</th><th>Role</th><th>Principal</th><th>Principal Type</th><th>Plane</th><th>Inherited</th><th>Scope</th></tr>")
    for resource in sorted(resources, key=lambda r: r["resourceName"]):
        for a in resource.get("assignments", []):
            inh = "Yes" if a["isInherited"] else "No"
            h.append(f'<tr><td>{escape(resource["resourceName"])}</td><td>{escape(resource["resourceType"])}</td><td>{escape(a["roleName"])}</td><td>{escape(a["principalName"])}</td><td>{escape(a["principalType"])}</td><td>{_plane_badge(a["plane"])}</td><td>{inh}</td><td><code class="scope-code">{escape(a["scope"])}</code></td></tr>')
    h.append("</table>")

    # -- footer --
    h.append("</div>\n</body>\n</html>")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(h))


# ── Markdown Report ─────────────────────────────────────────────────────────


def generate_markdown_report(
    findings: list[dict],
    rbac_data: dict,
    output_path: Path,
) -> None:
    """Generate comprehensive Markdown security report."""
    lines: list[str] = []
    metadata = rbac_data.get("metadata", {})
    resources = rbac_data.get("resources", [])

    sev_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f["severity"]] += 1
    total_assignments = sum(len(r.get("assignments", [])) for r in resources)

    # -- header --
    lines.append("# Azure RBAC Security Posture Report")
    lines.append("")
    lines.append(f'**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append("")

    # -- executive summary --
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f'- **Subscription:** {metadata.get("subscriptionName", "Unknown")} ({metadata.get("subscriptionId", "Unknown")})')
    lines.append(f'- **Resource Group:** {metadata.get("resourceGroup", "Unknown")}')
    lines.append(f'- **Resources Analyzed:** {metadata.get("resourceCount", 0)}')
    lines.append(f"- **Total Role Assignments:** {total_assignments}")
    lines.append(f'- **Include Inherited:** {"Yes" if metadata.get("includeInherited") else "No"}')
    lines.append(f"- **Security Findings:** {len(findings)}")
    lines.append(f'  - **HIGH:** {sev_counts.get("HIGH", 0)}')
    lines.append(f'  - **MEDIUM:** {sev_counts.get("MEDIUM", 0)}')
    lines.append(f'  - **LOW:** {sev_counts.get("LOW", 0)}')
    lines.append("")
    lines.append("---")
    lines.append("")

    # -- findings by severity --
    if not findings:
        lines.append("**No security findings detected.**")
        lines.append("")
    else:
        lines.append("## Security Findings")
        lines.append("")

        by_sev: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            by_sev[f["severity"]].append(f)

        for sev, emoji in [("HIGH", "HIGH"), ("MEDIUM", "MEDIUM"), ("LOW", "LOW")]:
            if sev not in by_sev:
                continue
            items = by_sev[sev]
            lines.append(f"### {sev} Severity ({len(items)} findings)")
            lines.append("")

            by_rule: dict[str, list[dict]] = defaultdict(list)
            for f in items:
                by_rule[f["ruleId"]].append(f)

            for rule_id in sorted(by_rule.keys()):
                rule_findings = by_rule[rule_id]
                rule_name = rule_findings[0]["ruleName"]
                lines.append(f"#### {rule_id}: {rule_name}")
                lines.append("")
                lines.append(f'*{rule_findings[0]["description"]}*')
                lines.append("")

                for i, f in enumerate(rule_findings, 1):
                    lines.append(f"**Finding {i}:**")
                    lines.append("")
                    lines.append(f'- **Resource:** {f["resource"]["name"]} ({f["resource"]["type"]})')
                    lines.append(f'- **Role:** {f["assignment"]["roleName"]}')
                    lines.append(f'- **Principal:** {f["assignment"]["principalName"]} ({f["assignment"]["principalType"]})')
                    lines.append(f'- **Scope:** `{f["assignment"]["scope"]}`')
                    lines.append(f'- **Details:** {f["details"]}')
                    lines.append("")
                    lines.append(f'**Recommendation:** {f["recommendation"]}')
                    lines.append("")
                    lines.append("**References:**")
                    lines.append("")
                    for ref in f["references"]:
                        lines.append(f'- [{ref["framework"]} {ref["id"]}: {ref["name"]}]({ref["url"]})')
                    lines.append("")
                    lines.append("---")
                    lines.append("")

    # -- RBAC inventory --
    lines.append("## RBAC Inventory")
    lines.append("")

    # by resource
    lines.append("### By Resource")
    lines.append("")
    for resource in sorted(resources, key=lambda r: r["resourceName"]):
        assignments = resource.get("assignments", [])
        if not assignments:
            continue
        lines.append(f'#### {resource["resourceName"]} ({resource["resourceType"]})')
        lines.append("")
        lines.append("| Role | Principal | Type | Plane | Inherited |")
        lines.append("|------|-----------|------|-------|-----------|")
        for a in assignments:
            inh = "Yes" if a["isInherited"] else "No"
            plane_label = "Data Plane" if "data" in a["plane"].lower() else "Control Plane"
            lines.append(f'| {a["roleName"]} | {a["principalName"]} | {a["principalType"]} | {plane_label} | {inh} |')
        lines.append("")

    # by role
    lines.append("### By Role")
    lines.append("")
    role_map: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for resource in resources:
        for a in resource.get("assignments", []):
            role_map[a["roleName"]].append((resource, a))
    for role_name in sorted(role_map.keys()):
        entries = role_map[role_name]
        lines.append(f"#### {role_name} ({len(entries)} assignments)")
        lines.append("")
        lines.append("| Resource | Type | Principal | Principal Type | Inherited |")
        lines.append("|----------|------|-----------|----------------|-----------|")
        for res, a in entries:
            inh = "Yes" if a["isInherited"] else "No"
            lines.append(f'| {res["resourceName"]} | {res["resourceType"]} | {a["principalName"]} | {a["principalType"]} | {inh} |')
        lines.append("")

    # by principal
    lines.append("### By Principal")
    lines.append("")
    principal_map: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for resource in resources:
        for a in resource.get("assignments", []):
            key = a["principalName"] or a["principalId"]
            principal_map[key].append((resource, a))
    for pname in sorted(principal_map.keys()):
        entries = principal_map[pname]
        ptype = entries[0][1]["principalType"]
        lines.append(f"#### {pname} ({ptype})")
        lines.append("")
        lines.append("| Resource | Type | Role | Plane | Inherited |")
        lines.append("|----------|------|------|-------|-----------|")
        for res, a in entries:
            inh = "Yes" if a["isInherited"] else "No"
            plane_label = "Data Plane" if "data" in a["plane"].lower() else "Control Plane"
            lines.append(f'| {res["resourceName"]} | {res["resourceType"]} | {a["roleName"]} | {plane_label} | {inh} |')
        lines.append("")

    # -- framework reference summary --
    lines.append("## Framework Reference Summary")
    lines.append("")
    fw_summary: dict[str, dict] = {}
    for f in findings:
        for ref in f["references"]:
            fw = ref["framework"]
            if fw not in fw_summary:
                fw_summary[fw] = {"controls": set(), "url": ref["url"]}
            fw_summary[fw]["controls"].add(ref["id"])
    if fw_summary:
        lines.append("| Framework | Controls Cited | URL |")
        lines.append("|-----------|---------------|-----|")
        for fw_name in sorted(fw_summary.keys()):
            info = fw_summary[fw_name]
            ctrls = ", ".join(sorted(info["controls"]))
            lines.append(f'| {fw_name} | {ctrls} | [{fw_name}]({info["url"]}) |')
        lines.append("")
    else:
        lines.append("No frameworks cited (no findings).")
        lines.append("")

    # -- appendix --
    lines.append("## Appendix: All Assignments")
    lines.append("")
    lines.append("| Resource | Type | Role | Principal | Principal Type | Plane | Inherited |")
    lines.append("|----------|------|------|-----------|----------------|-------|-----------|")
    for resource in sorted(resources, key=lambda r: r["resourceName"]):
        for a in resource.get("assignments", []):
            inh = "Yes" if a["isInherited"] else "No"
            plane_label = "Data Plane" if "data" in a["plane"].lower() else "Control Plane"
            lines.append(f'| {resource["resourceName"]} | {resource["resourceType"]} | {a["roleName"]} | {a["principalName"]} | {a["principalType"]} | {plane_label} | {inh} |')
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))


# ── CLI Entry Point ─────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Azure RBAC data for security issues",
        epilog=(
            "Examples:\n"
            "  python analyze_security.py output/rbac-my-rg-20260128.json\n"
            "  python analyze_security.py output/rbac-my-rg-20260128.json --output-dir ./custom\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="Path to RBAC extraction JSON file")
    parser.add_argument(
        "--output-dir",
        help="Base directory (default: parent of script directory)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"ERROR: {input_path} is not a file", file=sys.stderr)
        sys.exit(1)

    base_dir = Path(args.output_dir) if args.output_dir else Path(__file__).parent
    output_dir = base_dir / "output"
    reports_dir = base_dir / "reports"
    output_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)

    # Load & analyze
    print(f"Loading RBAC data: {input_path}")
    rbac_data = load_rbac_data(input_path)
    metadata = rbac_data.get("metadata", {})
    rg = metadata.get("resourceGroup", "unknown")

    print("Running security analysis (9 rules)...")
    findings = run_all_rules(rbac_data)

    # Severity summary
    sev_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f["severity"]] += 1

    # Write outputs
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    findings_path = output_dir / f"findings-{rg}-{timestamp}.json"
    html_path = reports_dir / f"security-report-{rg}.html"
    md_path = reports_dir / f"security-report-{rg}.md"

    print(f"Writing findings JSON: {findings_path}")
    write_findings_json(findings, metadata, findings_path)

    print(f"Generating HTML report: {html_path}")
    generate_html_report(findings, rbac_data, html_path)

    print(f"Generating Markdown report: {md_path}")
    generate_markdown_report(findings, rbac_data, md_path)

    # Console summary
    print()
    print("=" * 60)
    print("Security Analysis Summary")
    print("=" * 60)
    print(f"  Resource Group:     {rg}")
    print(f"  Resources Analyzed: {metadata.get('resourceCount', 0)}")
    print(f"  Total Findings:     {len(findings)}")
    print(f"    HIGH:   {sev_counts.get('HIGH', 0)}")
    print(f"    MEDIUM: {sev_counts.get('MEDIUM', 0)}")
    print(f"    LOW:    {sev_counts.get('LOW', 0)}")
    print("=" * 60)

    # Show rule breakdown
    rule_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        rule_counts[f["ruleId"]] += 1
    if rule_counts:
        print("\nFindings by Rule:")
        for rule_id in sorted(rule_counts.keys()):
            rule_name = SECURITY_RULES[rule_id]["name"]
            print(f"  {rule_id}: {rule_name} ({rule_counts[rule_id]})")
    print()


if __name__ == "__main__":
    main()
