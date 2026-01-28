# Azure RBAC Analysis Toolkit

This toolkit provides a comprehensive solution for analyzing Azure RBAC (Role-Based Access Control) assignments and identifying security anomalies.

## Scripts

### 1. Get-ResourceGroupRbac.ps1
PowerShell script that extracts RBAC role assignments from an Azure resource group.

**Usage:**
```powershell
# Basic usage
.\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg"

# Include inherited assignments from subscription/RG level
.\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg" -IncludeInherited

# Include group members
.\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg" -ListMembers

# Specify subscription
.\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg" -SubscriptionId "xxxx-xxxx"
```

**Output:** JSON file in `./output/rbac-{ResourceGroupName}-{timestamp}.json`

### 2. rbac_report.py
Generates comprehensive HTML and Markdown reports from RBAC JSON data.

**Features:**
- Executive summary with risk analysis
- High/Medium/Standard risk categorization
- Role assignments grouped by resource
- Role assignments grouped by role (Control Plane & Data Plane)
- Inherited assignments tracking
- Complete summary tables

**Usage:**
```bash
# Generate reports for all assignments
python rbac_report.py output/rbac-{rg-name}.json

# Filter for direct assignments only
python rbac_report.py output/rbac-{rg-name}.json --filter direct

# Filter for inherited assignments only
python rbac_report.py output/rbac-{rg-name}.json --filter inherited

# Specify output directory
python rbac_report.py output/rbac-{rg-name}.json --output-dir ./my-reports
```

**Output:** 
- `./reports/rbac_report-{rg-name}-{filter}.html`
- `./reports/rbac_report-{rg-name}-{filter}.md`

### 3. analyze_anomalies.py
Analyzes RBAC JSON data to identify security issues and misconfigurations.

**Detects:**
- **Role-Resource Mismatches**: Roles assigned to incorrect resource types
  - Azure AI Administrator on Key Vault (should only be on ML workspaces/Cognitive Services)
  - Key Vault roles on non-Key Vault resources
  - Storage roles on non-Storage resources
  - etc.
- **Overly Broad Permissions**: Generic roles like Owner/Contributor at resource level
- **Unusual Assignments**: Roles on passive infrastructure resources

**Usage:**
```bash
python analyze_anomalies.py output/rbac-{rg-name}.json
```

**Output:** 
- Console report with color-coded severity
- `./output/anomalies-{rg-name}.json` (detailed JSON)

### 4. anomalies_report.py
Generates formatted HTML and Markdown reports from anomalies JSON data.

**Features:**
- Anomalies grouped by severity (High/Medium/Low)
- Categorized by issue type
- Detailed information for each anomaly
- Complete summary table
- Quick navigation links

**Usage:**
```bash
python anomalies_report.py output/anomalies-{rg-name}.json

# Specify output directory
python anomalies_report.py output/anomalies-{rg-name}.json --output-dir ./my-reports
```

**Output:**
- `./reports/anomalies-{rg-name}-report.html`
- `./reports/anomalies-{rg-name}-report.md`

## Complete Workflow

```powershell
# 1. Extract RBAC data from Azure
.\Get-ResourceGroupRbac.ps1 -ResourceGroupName "sigma-ai-ucaia-sdc-prod-rg" -ListMembers

# 2. Generate RBAC reports (all assignments)
python rbac_report.py .\output\rbac-sigma-ai-ucaia-sdc-prod-rg-20260113-142707-withmembers.json

# 3. Analyze for anomalies
python analyze_anomalies.py .\output\rbac-sigma-ai-ucaia-sdc-prod-rg-20260113-142707-withmembers.json

# 4. Generate anomalies reports
python anomalies_report.py .\output\anomalies-rbac-sigma-ai-ucaia-sdc-prod-rg-20260113-142707-withmembers.json
```

## Report Types

### RBAC Reports
- **By Resource View**: See all role assignments for each resource
- **By Role View**: See all resources that have a specific role assigned
- **Risk Analysis**: High/Medium/Standard risk categorization
- **Group Members**: Shows members of groups that have assignments

### Anomalies Reports
- **High Severity**: Critical security issues (e.g., role-resource mismatches)
- **Medium Severity**: Best practice violations (e.g., overly broad permissions)
- **Low Severity**: Minor issues or unusual configurations

## Key Features

### Data Plane vs Control Plane
The toolkit distinguishes between:
- **Control Plane**: Management operations (create, delete, configure resources)
- **Data Plane**: Data access operations (read/write data, access secrets)

### Role Risk Classification
- **High Risk**: Owner, Contributor, Administrator roles
- **Medium Risk**: Operator, Editor, Writer roles
- **Standard**: Read-only and specific-purpose roles

### Anomaly Detection Rules
- Azure AI roles should only be on ML/Cognitive Services resources
- Key Vault roles should only be on Key Vault resources
- Storage roles should only be on Storage accounts
- Cognitive Services roles should only be on Cognitive Services
- Generic Contributor role is too broad for resource-level assignments

## Output Directory Structure

```
.
├── output/
│   ├── rbac-{rg-name}-{timestamp}.json          # Raw RBAC data
│   └── anomalies-{rg-name}.json                 # Anomalies data
└── reports/
    ├── rbac_report-{rg-name}-all.html           # Complete RBAC report (HTML)
    ├── rbac_report-{rg-name}-all.md             # Complete RBAC report (Markdown)
    ├── rbac_report-{rg-name}-direct.html        # Direct assignments only
    ├── rbac_report-{rg-name}-direct.md
    ├── rbac_report-{rg-name}-inherited.html     # Inherited assignments only
    ├── rbac_report-{rg-name}-inherited.md
    ├── anomalies-{rg-name}-report.html          # Anomalies report (HTML)
    └── anomalies-{rg-name}-report.md            # Anomalies report (Markdown)
```

## Tips

1. **Use -ListMembers** to see who's in security groups that have access
2. **Review anomalies first** to identify critical security issues
3. **Use the "By Role" view** to see all resources with a specific role (e.g., all resources with Azure AI Administrator)
4. **Filter reports** using `--filter direct` to exclude inherited assignments
5. **Open HTML reports in a browser** for the best viewing experience with collapsible sections

## Requirements

### PowerShell Script
- Azure PowerShell module (`Az`)
- Logged in to Azure (`Connect-AzAccount`)

### Python Scripts
- Python 3.7+
- No external dependencies (uses standard library only)
