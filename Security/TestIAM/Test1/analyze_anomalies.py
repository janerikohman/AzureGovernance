#!/usr/bin/env python3
"""
Analyze RBAC JSON for strange, harmful, or nonsensical role assignments.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Define role-to-resource type mappings (what roles SHOULD be on what resources)
ROLE_RESOURCE_RULES = {
    # Azure AI roles should only be on AI/ML resources
    'Azure AI Administrator': [
        'Microsoft.MachineLearningServices/workspaces',
        'Microsoft.CognitiveServices/accounts'
    ],
    'Azure AI Developer': [
        'Microsoft.MachineLearningServices/workspaces',
        'Microsoft.CognitiveServices/accounts'
    ],
    'Azure AI Inference Deployment Operator': [
        'Microsoft.MachineLearningServices/workspaces',
        'Microsoft.CognitiveServices/accounts'
    ],
    
    # Key Vault roles should only be on Key Vault
    'Key Vault Administrator': ['Microsoft.KeyVault/vaults'],
    'Key Vault Contributor': ['Microsoft.KeyVault/vaults'],
    'Key Vault Reader': ['Microsoft.KeyVault/vaults'],
    'Key Vault Secrets Officer': ['Microsoft.KeyVault/vaults'],
    'Key Vault Secrets User': ['Microsoft.KeyVault/vaults'],
    'Key Vault Crypto Officer': ['Microsoft.KeyVault/vaults'],
    'Key Vault Crypto User': ['Microsoft.KeyVault/vaults'],
    'Key Vault Crypto Service Encryption User': ['Microsoft.KeyVault/vaults'],
    'Key Vault Certificates Officer': ['Microsoft.KeyVault/vaults'],
    
    # Storage roles should only be on Storage accounts
    'Storage Blob Data Contributor': ['Microsoft.Storage/storageAccounts'],
    'Storage Blob Data Owner': ['Microsoft.Storage/storageAccounts'],
    'Storage Blob Data Reader': ['Microsoft.Storage/storageAccounts'],
    'Storage Queue Data Contributor': ['Microsoft.Storage/storageAccounts'],
    'Storage Queue Data Reader': ['Microsoft.Storage/storageAccounts'],
    'Storage Table Data Contributor': ['Microsoft.Storage/storageAccounts'],
    'Storage Table Data Reader': ['Microsoft.Storage/storageAccounts'],
    'Storage File Data Privileged Contributor': ['Microsoft.Storage/storageAccounts'],
    'Storage File Data Privileged Reader': ['Microsoft.Storage/storageAccounts'],
    
    # Cognitive Services roles should only be on Cognitive Services
    'Cognitive Services OpenAI User': ['Microsoft.CognitiveServices/accounts'],
    'Cognitive Services OpenAI Contributor': ['Microsoft.CognitiveServices/accounts'],
    'Cognitive Services User': ['Microsoft.CognitiveServices/accounts'],
    'Cognitive Services Contributor': ['Microsoft.CognitiveServices/accounts'],
    'Cognitive Services Usages Reader': ['Microsoft.CognitiveServices/accounts'],
    
    # Search roles should only be on Search services
    'Search Index Data Contributor': ['Microsoft.Search/searchServices'],
    'Search Index Data Reader': ['Microsoft.Search/searchServices'],
    'Search Service Contributor': ['Microsoft.Search/searchServices'],
    
    # Container Registry roles should only be on ACR
    'AcrPull': ['Microsoft.ContainerRegistry/registries'],
    'AcrPush': ['Microsoft.ContainerRegistry/registries'],
    'AcrDelete': ['Microsoft.ContainerRegistry/registries'],
    'AcrImageSigner': ['Microsoft.ContainerRegistry/registries'],
    
    # Cosmos DB roles should only be on Cosmos DB
    'Cosmos DB Account Reader Role': ['Microsoft.DocumentDB/databaseAccounts'],
    'Cosmos DB Operator': ['Microsoft.DocumentDB/databaseAccounts'],
    'CosmosBackupOperator': ['Microsoft.DocumentDB/databaseAccounts'],
    'DocumentDB Account Contributor': ['Microsoft.DocumentDB/databaseAccounts'],
    
    # Application Insights should only be on Insights components
    'Application Insights Component Contributor': ['Microsoft.Insights/components'],
    'Application Insights Snapshot Debugger': ['Microsoft.Insights/components'],
}

# Roles that should generally NOT be assigned at resource level (too broad)
OVERLY_BROAD_ROLES = [
    'Owner',
    'Contributor',
    'User Access Administrator'
]

# Resource types that should rarely have direct role assignments
PASSIVE_RESOURCE_TYPES = [
    'Microsoft.Network/networkInterfaces',
    'Microsoft.Network/privateEndpoints',
    'Microsoft.Network/privateDnsZones',
    'Microsoft.Network/virtualNetworks/subnets'
]


def load_rbac_file(filepath: Path):
    """Load RBAC JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_anomalies(rbac_data):
    """Analyze RBAC data for anomalies."""
    anomalies = []
    
    for resource in rbac_data.get('resources', []):
        resource_name = resource['resourceName']
        resource_type = resource['resourceType']
        resource_id = resource['resourceId']
        
        # Check both control and data plane
        for plane, plane_name in [('controlPlane', 'Control Plane'), ('dataPlane', 'Data Plane')]:
            for role_name, assignments in resource[plane].items():
                for assignment in assignments:
                    # Check 1: Role-Resource type mismatch
                    if role_name in ROLE_RESOURCE_RULES:
                        allowed_types = ROLE_RESOURCE_RULES[role_name]
                        if resource_type not in allowed_types:
                            anomalies.append({
                                'severity': 'HIGH',
                                'category': 'Role-Resource Mismatch',
                                'resource_name': resource_name,
                                'resource_type': resource_type,
                                'role': role_name,
                                'principal': assignment['displayName'],
                                'principal_type': assignment['principalType'],
                                'plane': plane_name,
                                'reason': f"'{role_name}' role should only be assigned to: {', '.join(allowed_types)}, not {resource_type}",
                                'scope': assignment['scope']
                            })
                    
                    # Check 2: Overly broad roles at resource level
                    if role_name in OVERLY_BROAD_ROLES:
                        anomalies.append({
                            'severity': 'MEDIUM',
                            'category': 'Overly Broad Permission',
                            'resource_name': resource_name,
                            'resource_type': resource_type,
                            'role': role_name,
                            'principal': assignment['displayName'],
                            'principal_type': assignment['principalType'],
                            'plane': plane_name,
                            'reason': f"'{role_name}' is too broad for resource-level assignment. Consider more specific roles.",
                            'scope': assignment['scope']
                            
                        })
                    
                    # Check 3: Assignments on passive infrastructure resources
                    if resource_type in PASSIVE_RESOURCE_TYPES:
                        anomalies.append({
                            'severity': 'LOW',
                            'category': 'Unusual Target Resource',
                            'resource_name': resource_name,
                            'resource_type': resource_type,
                            'role': role_name,
                            'principal': assignment['displayName'],
                            'principal_type': assignment['principalType'],
                            'plane': plane_name,
                            'reason': f"Role assignment on {resource_type} is unusual - these resources typically don't need direct assignments",
                            'scope': assignment['scope']
                        })
    
    return anomalies


def print_anomalies_report(anomalies, output_format='text'):
    """Print anomalies report."""
    if not anomalies:
        print("✅ No anomalies detected!")
        return
    
    # Group by severity
    by_severity = defaultdict(list)
    for anomaly in anomalies:
        by_severity[anomaly['severity']].append(anomaly)
    
    severity_order = ['HIGH', 'MEDIUM', 'LOW']
    severity_emoji = {
        'HIGH': '🔴',
        'MEDIUM': '🟠',
        'LOW': '🟡'
    }
    
    print("="*80)
    print("🔍 RBAC ANOMALY ANALYSIS REPORT")
    print("="*80)
    print(f"\nTotal anomalies found: {len(anomalies)}")
    print(f"  - HIGH severity: {len(by_severity['HIGH'])}")
    print(f"  - MEDIUM severity: {len(by_severity['MEDIUM'])}")
    print(f"  - LOW severity: {len(by_severity['LOW'])}")
    print()
    
    for severity in severity_order:
        if severity not in by_severity:
            continue
        
        anomalies_list = by_severity[severity]
        print(f"\n{severity_emoji[severity]} {severity} SEVERITY ({len(anomalies_list)} issues)")
        print("-"*80)
        
        # Group by category
        by_category = defaultdict(list)
        for anomaly in anomalies_list:
            by_category[anomaly['category']].append(anomaly)
        
        for category, items in by_category.items():
            print(f"\n  📌 {category} ({len(items)} issues):")
            for i, anomaly in enumerate(items, 1):
                print(f"\n    {i}. Resource: {anomaly['resource_name']}")
                print(f"       Type: {anomaly['resource_type']}")
                print(f"       Role: {anomaly['role']} ({anomaly['plane']})")
                print(f"       Principal: {anomaly['principal']} ({anomaly['principal_type']})")
                print(f"       ⚠️  {anomaly['reason']}")
    
    print("\n" + "="*80)


def save_anomalies_json(anomalies, output_path, rbac_metadata=None):
    """Save anomalies to JSON file."""
    output_data = {
        'summary': {
            'total': len(anomalies),
            'high': len([a for a in anomalies if a['severity'] == 'HIGH']),
            'medium': len([a for a in anomalies if a['severity'] == 'MEDIUM']),
            'low': len([a for a in anomalies if a['severity'] == 'LOW'])
        },
        'anomalies': anomalies
    }
    
    # Include metadata from original RBAC file if available
    if rbac_metadata:
        output_data['metadata'] = rbac_metadata
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    print(f"\n📄 Detailed report saved to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_anomalies.py <rbac-json-file>")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"Error: {input_path} is not a file")
        sys.exit(1)
    
    print(f"Loading RBAC file: {input_path}")
    rbac_data = load_rbac_file(input_path)
    
    print("Analyzing for anomalies...")
    anomalies = analyze_anomalies(rbac_data)
    
    # Print report
    print_anomalies_report(anomalies)
    
    # Save detailed JSON with metadata
    output_path = input_path.parent / f"anomalies-{input_path.stem}.json"
    save_anomalies_json(anomalies, output_path, rbac_data.get('metadata'))


if __name__ == '__main__':
    main()
