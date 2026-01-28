#!/usr/bin/env python3
"""
Azure RBAC Extraction using Azure CLI (az).

Extracts all RBAC role assignments for resources in a specified resource group
and classifies them as control plane or data plane.

Prerequisites:
    - Azure CLI installed and authenticated (az login)
    - Appropriate read permissions on the target resource group

Usage:
    python extract_rbac.py -g my-rg
    python extract_rbac.py -g my-rg --include-inherited
    python extract_rbac.py -g my-rg -s <subscription-id> --include-inherited
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from constants import is_data_plane_role

# Find the az CLI executable (handles Windows where it's az.cmd)
_AZ_CMD = shutil.which("az")


def run_az_command(args: list[str]) -> dict | list:
    """Run an az CLI command and return parsed JSON output."""
    if not _AZ_CMD:
        print(
            "ERROR: Azure CLI (az) not found in PATH. "
            "Install from https://aka.ms/installazurecli",
            file=sys.stderr,
        )
        sys.exit(1)

    cmd = [_AZ_CMD] + args + ["-o", "json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        print(
            "ERROR: Azure CLI (az) not found. "
            "Install from https://aka.ms/installazurecli",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(
            f"ERROR: az command timed out: {' '.join(cmd)}",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode != 0:
        print(f"ERROR: az command failed: {' '.join(cmd)}", file=sys.stderr)
        print(f"  stderr: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    return json.loads(result.stdout)


def get_subscription_info(subscription_id: str | None = None) -> dict:
    """Get subscription id and display name."""
    if subscription_id:
        info = run_az_command(["account", "show", "-s", subscription_id])
    else:
        info = run_az_command(["account", "show"])
    return {
        "id": info["id"],
        "name": info.get("name", info["id"]),
    }


def get_resources(resource_group: str) -> list[dict]:
    """Get all resources in a resource group."""
    raw = run_az_command(["resource", "list", "-g", resource_group])
    return [
        {
            "name": r["name"],
            "type": r["type"],
            "id": r["id"],
        }
        for r in raw
    ]


def get_role_assignments(scope: str, include_inherited: bool = False) -> list[dict]:
    """Get role assignments for a given scope using az CLI."""
    args = ["role", "assignment", "list", "--scope", scope]
    if include_inherited:
        args.append("--include-inherited")
    return run_az_command(args)


def classify_assignment(assignment: dict, resource_id: str) -> dict:
    """Transform an az CLI role assignment into our normalized format."""
    role_name = assignment.get("roleDefinitionName", "Unknown")
    scope = assignment.get("scope", "")
    is_inherited = scope.lower() != resource_id.lower()
    plane = "dataPlane" if is_data_plane_role(role_name) else "controlPlane"

    principal_name = (
        assignment.get("principalName", "")
        or assignment.get("principalId", "Unknown")
    )

    return {
        "roleName": role_name,
        "principalName": principal_name,
        "principalType": assignment.get("principalType", "Unknown"),
        "principalId": assignment.get("principalId", ""),
        "scope": scope,
        "isInherited": is_inherited,
        "plane": plane,
    }


def extract_rbac(
    resource_group: str,
    subscription_id: str | None = None,
    include_inherited: bool = False,
) -> dict:
    """Main extraction: list resources, get assignments, classify."""
    # Set subscription context if specified
    if subscription_id:
        run_az_command(["account", "set", "-s", subscription_id])

    sub_info = get_subscription_info(subscription_id)
    print(f"  Subscription: {sub_info['name']} ({sub_info['id']})")

    # Get resources
    resources = get_resources(resource_group)
    print(f"  Resources found: {len(resources)}")

    total_assignments = 0
    report_resources = []

    for i, res in enumerate(resources, 1):
        print(f"  [{i}/{len(resources)}] {res['name']} ({res['type']})")

        raw_assignments = get_role_assignments(res["id"], include_inherited)

        if not include_inherited:
            raw_assignments = [
                a for a in raw_assignments
                if a.get("scope", "").lower() == res["id"].lower()
            ]

        assignments = [
            classify_assignment(a, res["id"]) for a in raw_assignments
        ]
        total_assignments += len(assignments)

        report_resources.append({
            "resourceName": res["name"],
            "resourceType": res["type"],
            "resourceId": res["id"],
            "assignments": assignments,
        })

    return {
        "metadata": {
            "subscriptionId": sub_info["id"],
            "subscriptionName": sub_info["name"],
            "resourceGroup": resource_group,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "includeInherited": include_inherited,
            "resourceCount": len(resources),
            "totalAssignments": total_assignments,
            "toolVersion": "test2-1.0",
        },
        "resources": report_resources,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract RBAC assignments from an Azure resource group using az CLI",
    )
    parser.add_argument(
        "-g", "--resource-group", required=True, help="Resource group name",
    )
    parser.add_argument(
        "-s", "--subscription", help="Subscription ID (optional)",
    )
    parser.add_argument(
        "--include-inherited",
        action="store_true",
        help="Include inherited assignments from parent scopes",
    )
    args = parser.parse_args()

    print(f"Extracting RBAC for resource group: {args.resource_group}")
    data = extract_rbac(
        args.resource_group, args.subscription, args.include_inherited,
    )

    # Write output
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = output_dir / f"rbac-{args.resource_group}-{timestamp}.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"\nRBAC data saved to: {output_path}")
    print(f"  Resources: {data['metadata']['resourceCount']}")
    print(f"  Total assignments: {data['metadata']['totalAssignments']}")


if __name__ == "__main__":
    main()
