"""
Shared constants for Azure RBAC security posture analysis.

Central definitions for role classification, resource type mappings,
compliance framework references, and security rule metadata.
"""

import re

# ---------------------------------------------------------------------------
# Data Plane vs Control Plane classification
# ---------------------------------------------------------------------------

DATA_PLANE_ROLE_PATTERNS: list[str] = [
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

CONTROL_PLANE_ROLES: list[str] = [
    "owner",
    "contributor",
    "reader",
    "user access administrator",
    "storage account contributor",
    "key vault contributor",
    "cognitive services contributor",
    "documentdb account contributor",
]


def is_data_plane_role(role_name: str) -> bool:
    """Return True if the role is a data-plane role, False otherwise."""
    role_lower = role_name.lower()
    if role_lower in CONTROL_PLANE_ROLES:
        return False
    for pattern in DATA_PLANE_ROLE_PATTERNS:
        if pattern in role_lower:
            if "contributor" in role_lower and "data" not in role_lower:
                return False
            return True
    return False


# ---------------------------------------------------------------------------
# Role-Resource type expected mappings  (for RBAC-003)
# ---------------------------------------------------------------------------

ROLE_RESOURCE_RULES: dict[str, list[str]] = {
    # Azure AI / ML
    "Azure AI Administrator": [
        "Microsoft.MachineLearningServices/workspaces",
        "Microsoft.CognitiveServices/accounts",
    ],
    "Azure AI Developer": [
        "Microsoft.MachineLearningServices/workspaces",
        "Microsoft.CognitiveServices/accounts",
    ],
    "Azure AI Inference Deployment Operator": [
        "Microsoft.MachineLearningServices/workspaces",
        "Microsoft.CognitiveServices/accounts",
    ],
    # Key Vault
    "Key Vault Administrator": ["Microsoft.KeyVault/vaults"],
    "Key Vault Contributor": ["Microsoft.KeyVault/vaults"],
    "Key Vault Reader": ["Microsoft.KeyVault/vaults"],
    "Key Vault Secrets Officer": ["Microsoft.KeyVault/vaults"],
    "Key Vault Secrets User": ["Microsoft.KeyVault/vaults"],
    "Key Vault Crypto Officer": ["Microsoft.KeyVault/vaults"],
    "Key Vault Crypto User": ["Microsoft.KeyVault/vaults"],
    "Key Vault Crypto Service Encryption User": ["Microsoft.KeyVault/vaults"],
    "Key Vault Certificates Officer": ["Microsoft.KeyVault/vaults"],
    # Storage
    "Storage Blob Data Contributor": ["Microsoft.Storage/storageAccounts"],
    "Storage Blob Data Owner": ["Microsoft.Storage/storageAccounts"],
    "Storage Blob Data Reader": ["Microsoft.Storage/storageAccounts"],
    "Storage Queue Data Contributor": ["Microsoft.Storage/storageAccounts"],
    "Storage Queue Data Reader": ["Microsoft.Storage/storageAccounts"],
    "Storage Table Data Contributor": ["Microsoft.Storage/storageAccounts"],
    "Storage Table Data Reader": ["Microsoft.Storage/storageAccounts"],
    "Storage File Data Privileged Contributor": ["Microsoft.Storage/storageAccounts"],
    "Storage File Data Privileged Reader": ["Microsoft.Storage/storageAccounts"],
    # Cognitive Services
    "Cognitive Services OpenAI User": ["Microsoft.CognitiveServices/accounts"],
    "Cognitive Services OpenAI Contributor": ["Microsoft.CognitiveServices/accounts"],
    "Cognitive Services User": ["Microsoft.CognitiveServices/accounts"],
    "Cognitive Services Contributor": ["Microsoft.CognitiveServices/accounts"],
    "Cognitive Services Usages Reader": ["Microsoft.CognitiveServices/accounts"],
    # Search
    "Search Index Data Contributor": ["Microsoft.Search/searchServices"],
    "Search Index Data Reader": ["Microsoft.Search/searchServices"],
    "Search Service Contributor": ["Microsoft.Search/searchServices"],
    # Container Registry
    "AcrPull": ["Microsoft.ContainerRegistry/registries"],
    "AcrPush": ["Microsoft.ContainerRegistry/registries"],
    "AcrDelete": ["Microsoft.ContainerRegistry/registries"],
    "AcrImageSigner": ["Microsoft.ContainerRegistry/registries"],
    # Cosmos DB
    "Cosmos DB Account Reader Role": ["Microsoft.DocumentDB/databaseAccounts"],
    "Cosmos DB Operator": ["Microsoft.DocumentDB/databaseAccounts"],
    "CosmosBackupOperator": ["Microsoft.DocumentDB/databaseAccounts"],
    "DocumentDB Account Contributor": ["Microsoft.DocumentDB/databaseAccounts"],
    # Application Insights
    "Application Insights Component Contributor": ["Microsoft.Insights/components"],
    "Application Insights Snapshot Debugger": ["Microsoft.Insights/components"],
}


# ---------------------------------------------------------------------------
# Privilege / risk constants
# ---------------------------------------------------------------------------

OVERLY_PRIVILEGED_ROLES: list[str] = [
    "Owner",
    "Contributor",
    "User Access Administrator",
]

BROAD_ROLES: list[str] = [
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
]

PASSIVE_RESOURCE_TYPES: list[str] = [
    "Microsoft.Network/networkInterfaces",
    "Microsoft.Network/privateEndpoints",
    "Microsoft.Network/privateDnsZones",
    "Microsoft.Network/virtualNetworks/subnets",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
]

EXCESSIVE_PRIVILEGE_THRESHOLD: int = 3

GUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# External framework references
# ---------------------------------------------------------------------------

FRAMEWORK_REFERENCES: dict[str, dict[str, str]] = {
    # NIST SP 800-53 Rev. 5
    "NIST-AC-2": {
        "id": "AC-2",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Account Management",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/",
        "description": (
            "Manage system accounts, including establishing, activating, "
            "modifying, reviewing, disabling, and removing accounts."
        ),
    },
    "NIST-AC-3": {
        "id": "AC-3",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Access Enforcement",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-3/",
        "description": (
            "Enforce approved authorizations for logical access to "
            "information and system resources."
        ),
    },
    "NIST-AC-5": {
        "id": "AC-5",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Separation of Duties",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-5/",
        "description": (
            "Separate duties of individuals to prevent malevolent activity."
        ),
    },
    "NIST-AC-6": {
        "id": "AC-6",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Least Privilege",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/",
        "description": (
            "Employ the principle of least privilege, allowing only "
            "authorized accesses for users and processes."
        ),
    },
    "NIST-AC-6(1)": {
        "id": "AC-6(1)",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Authorize Access to Security Functions",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/ac-6-1/",
        "description": (
            "Explicitly authorize access to security-relevant functions "
            "and security-relevant information."
        ),
    },
    "NIST-AC-6(5)": {
        "id": "AC-6(5)",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Privileged Accounts",
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-6/ac-6-5/",
        "description": (
            "Restrict privileged accounts on the system to defined "
            "personnel or roles."
        ),
    },
    # Microsoft Cloud Security Benchmark (MCSB)
    "MCSB-PA-1": {
        "id": "PA-1",
        "framework": "Microsoft Cloud Security Benchmark",
        "name": "Separate and limit highly privileged/administrative users",
        "url": (
            "https://learn.microsoft.com/en-us/security/benchmark/azure/"
            "mcsb-privileged-access#pa-1-separate-and-limit-highly-"
            "privilegedadministrative-users"
        ),
        "description": (
            "Limit the number of highly privileged user accounts and "
            "protect these accounts at an elevated level."
        ),
    },
    "MCSB-PA-2": {
        "id": "PA-2",
        "framework": "Microsoft Cloud Security Benchmark",
        "name": "Avoid standing access for user accounts and permissions",
        "url": (
            "https://learn.microsoft.com/en-us/security/benchmark/azure/"
            "mcsb-privileged-access#pa-2-avoid-standing-access-for-user-"
            "accounts-and-permissions"
        ),
        "description": (
            "Instead of creating standing privileges, use just-in-time "
            "(JIT) mechanism to assign privileged access."
        ),
    },
    "MCSB-PA-7": {
        "id": "PA-7",
        "framework": "Microsoft Cloud Security Benchmark",
        "name": "Follow just enough administration (least privilege) principle",
        "url": (
            "https://learn.microsoft.com/en-us/security/benchmark/azure/"
            "mcsb-privileged-access#pa-7-follow-just-enough-administration-"
            "least-privilege-principle"
        ),
        "description": (
            "Follow the least privilege principle to manage permissions "
            "at fine-grained level."
        ),
    },
    "MCSB-IM-3": {
        "id": "IM-3",
        "framework": "Microsoft Cloud Security Benchmark",
        "name": "Manage application identities securely and automatically",
        "url": (
            "https://learn.microsoft.com/en-us/security/benchmark/azure/"
            "mcsb-identity-management#im-3-manage-application-identities-"
            "securely-and-automatically"
        ),
        "description": (
            "Use managed application identities instead of creating "
            "human service accounts."
        ),
    },
    # Microsoft Well-Architected Framework - Security Pillar
    "WAF-SE05": {
        "id": "SE:05",
        "framework": "Microsoft Well-Architected Framework - Security Pillar",
        "name": "Identity and Access Management",
        "url": (
            "https://learn.microsoft.com/en-us/azure/well-architected/"
            "security/identity-access"
        ),
        "description": (
            "Apply identity and access management (IAM) controls to all "
            "workload access."
        ),
    },
    # CIS Microsoft Azure Foundations Benchmark
    "CIS-1.1": {
        "id": "1.1",
        "framework": "CIS Microsoft Azure Foundations Benchmark v2.1.0",
        "name": "Ensure Security Defaults is enabled on Microsoft Entra ID",
        "url": "https://www.cisecurity.org/benchmark/azure",
        "description": (
            "Security defaults provide secure default settings managed "
            "on behalf of organizations."
        ),
    },
    "CIS-1.23": {
        "id": "1.23",
        "framework": "CIS Microsoft Azure Foundations Benchmark v2.1.0",
        "name": "Ensure That No Custom Subscription Administrator Roles Are Created",
        "url": "https://www.cisecurity.org/benchmark/azure",
        "description": (
            "Minimize custom subscription owner roles to reduce "
            "attack surface."
        ),
    },
    "CIS-1.25": {
        "id": "1.25",
        "framework": "CIS Microsoft Azure Foundations Benchmark v2.1.0",
        "name": "Ensure fewer than 5 users have Global Administrator role",
        "url": "https://www.cisecurity.org/benchmark/azure",
        "description": (
            "Limit the number of Global Administrator role designations "
            "to less than five."
        ),
    },
    # OWASP
    "OWASP-A01": {
        "id": "A01:2021",
        "framework": "OWASP Top 10 2021",
        "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "description": (
            "Access control enforces policy such that users cannot act "
            "outside of their intended permissions."
        ),
    },
}


# ---------------------------------------------------------------------------
# Security rule definitions
# ---------------------------------------------------------------------------

SECURITY_RULES: dict[str, dict] = {
    "RBAC-001": {
        "id": "RBAC-001",
        "name": "Overly Privileged Roles at Resource Level",
        "description": (
            "Owner, Contributor, or User Access Administrator assigned "
            "directly on a specific resource rather than at resource group "
            "or subscription scope. These roles grant full control plane "
            "access and should be scoped at higher levels with more "
            "restrictive, purpose-specific roles used at resource level."
        ),
        "severity": "HIGH",
        "category": "Excessive Privileges",
        "recommendation": (
            "Replace with resource-specific roles (e.g., 'Storage Blob "
            "Data Contributor' instead of 'Contributor' on a storage "
            "account). If broad access is required, assign at resource "
            "group scope instead."
        ),
        "references": [
            "NIST-AC-6", "NIST-AC-6(1)", "MCSB-PA-7", "WAF-SE05", "OWASP-A01",
        ],
    },
    "RBAC-002": {
        "id": "RBAC-002",
        "name": "Individual User Assignments",
        "description": (
            "Role assigned directly to an individual user principal "
            "instead of a security group. Individual assignments are "
            "harder to audit, don't scale, and create management "
            "overhead when employees change roles."
        ),
        "severity": "MEDIUM",
        "category": "Identity Governance",
        "recommendation": (
            "Create Entra ID security groups for each role pattern and "
            "assign roles to groups. Manage access by adding/removing "
            "users from groups."
        ),
        "references": ["NIST-AC-2", "MCSB-PA-2", "WAF-SE05", "CIS-1.1"],
    },
    "RBAC-003": {
        "id": "RBAC-003",
        "name": "Role-Resource Type Mismatch",
        "description": (
            "A role designed for a specific Azure service is assigned to "
            "an unrelated resource type (e.g., Key Vault Administrator on "
            "a Storage Account). This indicates misconfiguration and the "
            "role grants no meaningful permissions on the target resource."
        ),
        "severity": "HIGH",
        "category": "Misconfiguration",
        "recommendation": (
            "Remove the mismatched role assignment. Assign the correct "
            "resource-specific role to the intended resource type."
        ),
        "references": [
            "NIST-AC-3", "NIST-AC-6", "MCSB-PA-7", "WAF-SE05", "OWASP-A01",
        ],
    },
    "RBAC-004": {
        "id": "RBAC-004",
        "name": "Excessive High-Privilege Principals per Resource",
        "description": (
            f"More than {EXCESSIVE_PRIVILEGE_THRESHOLD} principals have "
            "Owner or Contributor role on a single resource. High "
            "concentration of privileged access increases blast radius "
            "of compromised accounts."
        ),
        "severity": "HIGH",
        "category": "Excessive Privileges",
        "recommendation": (
            f"Reduce the number of Owner/Contributor assignments to at "
            f"most {EXCESSIVE_PRIVILEGE_THRESHOLD}. Use more specific "
            "roles and consolidate access through security groups."
        ),
        "references": [
            "NIST-AC-6(5)", "MCSB-PA-1", "CIS-1.25", "WAF-SE05", "OWASP-A01",
        ],
    },
    "RBAC-005": {
        "id": "RBAC-005",
        "name": "Service Principal with Broad Roles",
        "description": (
            "A service principal (application or managed identity) has "
            "Owner, Contributor, or User Access Administrator role. "
            "Service principals operate without MFA and often have "
            "persistent credentials, making broad roles especially "
            "dangerous."
        ),
        "severity": "HIGH",
        "category": "Service Identity Risk",
        "recommendation": (
            "Assign the minimum required role to the service principal. "
            "Prefer managed identities over app registrations. Use "
            "custom roles if built-in roles are too broad."
        ),
        "references": [
            "NIST-AC-6(5)", "MCSB-IM-3", "MCSB-PA-7", "WAF-SE05", "OWASP-A01",
        ],
    },
    "RBAC-006": {
        "id": "RBAC-006",
        "name": "Orphaned/Unknown Principal",
        "description": (
            "A role assignment references a principal that cannot be "
            "resolved (displays as a GUID with 'Unknown' type). This "
            "typically means the Entra ID identity was deleted but the "
            "role assignment remains, creating confusion and potential "
            "reuse risk."
        ),
        "severity": "MEDIUM",
        "category": "Hygiene",
        "recommendation": (
            "Remove the orphaned role assignment. Implement a regular "
            "RBAC hygiene review process to clean up stale assignments."
        ),
        "references": ["NIST-AC-2", "MCSB-PA-2", "WAF-SE05"],
    },
    "RBAC-007": {
        "id": "RBAC-007",
        "name": "Separation of Duties Violation",
        "description": (
            "The same principal has both control plane and data plane "
            "roles on the same resource. This violates separation of "
            "duties: the principal can both manage the resource "
            "configuration AND access its data."
        ),
        "severity": "MEDIUM",
        "category": "Separation of Duties",
        "recommendation": (
            "Separate control plane and data plane access between "
            "different principals or groups. If one identity truly "
            "needs both, document the exception."
        ),
        "references": [
            "NIST-AC-5", "NIST-AC-6", "MCSB-PA-1", "WAF-SE05", "OWASP-A01",
        ],
    },
    "RBAC-008": {
        "id": "RBAC-008",
        "name": "Assignments on Passive Infrastructure",
        "description": (
            "Role assignments exist on passive infrastructure resources "
            "(NICs, private endpoints, private DNS zones) that typically "
            "do not need direct RBAC assignments. Access to these "
            "resources is usually managed at the resource group or "
            "parent resource level."
        ),
        "severity": "LOW",
        "category": "Noise / Misconfiguration",
        "recommendation": (
            "Review whether these assignments are intentional. Typically "
            "RBAC on passive network resources is unnecessary and can "
            "be removed."
        ),
        "references": ["NIST-AC-6", "MCSB-PA-7", "WAF-SE05"],
    },
    "RBAC-009": {
        "id": "RBAC-009",
        "name": "Inherited Broad Permissions",
        "description": (
            "Owner, Contributor, or User Access Administrator role is "
            "inherited from a parent scope (subscription or management "
            "group). While inheritance is normal, broad roles cascading "
            "from above give wide access to all resources and should "
            "be documented."
        ),
        "severity": "MEDIUM",
        "category": "Inherited Risk",
        "recommendation": (
            "Review whether the inherited broad permission is "
            "intentional. Consider using more specific roles at the "
            "parent scope, or use deny assignments to restrict "
            "inherited access where needed."
        ),
        "references": [
            "NIST-AC-6", "NIST-AC-6(1)", "MCSB-PA-7", "CIS-1.23", "WAF-SE05",
        ],
    },
}
