#!/usr/bin/env python3
"""
Azure Resource Group RBAC Report - JSON Output

Requirements:
    pip install -r requirements.txt

Usage:
    python get_resource_group_rbac.py -g my-rg
    python get_resource_group_rbac.py -g my-rg --include-inherited > report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from collections import defaultdict

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient


DATA_PLANE_ROLE_PATTERNS = [
    "storage blob data",
    "storage queue data",
    "storage table data",
    "storage file data",
    "key vault administrator",
    "key vault certificates officer",
    "key vault crypto officer",
    "key vault crypto service encryption user",
    "key vault crypto user",
    "key vault reader",
    "key vault secrets officer",
    "key vault secrets user",
    "cosmos db account reader role",
    "cosmos db operator",
    "cosmosbackupoperator",
    "cosmos db built-in data",
    "azure service bus data",
    "azure event hubs data",
    "cognitive services",
    "azure ai developer",
    "azure ai inference",
    "search index data",
    "app configuration data",
    "signalr",
    "web pubsub service",
    "iot hub data",
    "azure digital twins data",
    "grafana",
    "fhir data",
    "attestation reader",
]

CONTROL_PLANE_ROLES = [
    "owner", "contributor", "reader", "user access administrator",
    "storage account contributor", "key vault contributor",
    "cognitive services contributor", "documentdb account contributor",
]


def is_data_plane_role(role_name: str) -> bool:
    role_lower = role_name.lower()
    if role_lower in CONTROL_PLANE_ROLES:
        return False
    for pattern in DATA_PLANE_ROLE_PATTERNS:
        if pattern in role_lower:
            if "contributor" in role_lower and "data" not in role_lower:
                return False
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Generate RBAC JSON report for Azure resource group")
    parser.add_argument("-g", "--resource-group", required=True, help="Resource group name")
    parser.add_argument("-s", "--subscription", help="Subscription ID")
    parser.add_argument("--include-inherited", action="store_true", help="Include inherited assignments")
    args = parser.parse_args()

    credential = DefaultAzureCredential()

    # Get subscription ID
    subscription_id = args.subscription
    if not subscription_id:
        sub_client = SubscriptionClient(credential)
        subscription_id = next(sub_client.subscriptions.list()).subscription_id

    resource_client = ResourceManagementClient(credential, subscription_id)
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    # Cache role definitions
    role_cache = {}

    def get_role_name(role_definition_id: str) -> str:
        if role_definition_id not in role_cache:
            try:
                role_def = auth_client.role_definitions.get_by_id(role_definition_id)
                role_cache[role_definition_id] = role_def.role_name
            except Exception:
                role_cache[role_definition_id] = role_definition_id.split("/")[-1]
        return role_cache[role_definition_id]

    # Get resources
    resources = list(resource_client.resources.list_by_resource_group(args.resource_group))
    report_data = []

    for resource in resources:
        resource_report = {
            "resourceName": resource.name,
            "resourceType": resource.type,
            "resourceId": resource.id,
            "controlPlane": defaultdict(list),
            "dataPlane": defaultdict(list),
        }

        assignments = list(auth_client.role_assignments.list_for_scope(resource.id))

        if not args.include_inherited:
            assignments = [a for a in assignments if a.scope.lower() == resource.id.lower()]

        for assignment in assignments:
            role_name = get_role_name(assignment.role_definition_id)
            is_inherited = assignment.scope.lower() != resource.id.lower()

            assignment_info = {
                "principalId": assignment.principal_id,
                "principalType": assignment.principal_type or "Unknown",
                "displayName": assignment.principal_id,  # Graph API needed for real name
                "scope": assignment.scope,
                "isInherited": is_inherited,
            }

            target = "dataPlane" if is_data_plane_role(role_name) else "controlPlane"
            resource_report[target][role_name].append(assignment_info)

        # Convert defaultdicts to regular dicts
        resource_report["controlPlane"] = dict(resource_report["controlPlane"])
        resource_report["dataPlane"] = dict(resource_report["dataPlane"])
        report_data.append(resource_report)

    # Get subscription name
    sub_client = SubscriptionClient(credential)
    subscription_name = subscription_id
    for sub in sub_client.subscriptions.list():
        if sub.subscription_id == subscription_id:
            subscription_name = sub.display_name
            break

    output = {
        "metadata": {
            "subscriptionId": subscription_id,
            "subscriptionName": subscription_name,
            "resourceGroup": args.resource_group,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "includeInherited": args.include_inherited,
            "resourceCount": len(resources),
        },
        "resources": report_data,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
