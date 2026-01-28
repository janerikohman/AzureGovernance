# RBAC Report Filtering Guide

The `rbac_report.py` script now supports filtering to generate reports based on assignment scope and inheritance level.

## Usage

```bash
python rbac_report.py <json_file> [--filter all|direct|inherited] [--output-dir DIR]
```

## Filter Options

### `--filter all` (Default)
Shows **all assignments** in the RBAC JSON file.

```bash
python rbac_report.py .\output\report.json --filter all
```

**Use case:** Complete security posture review including all inherited assignments.

---

### `--filter direct`
Shows **only direct assignments at the resource level** (not inherited from parent scopes).

```bash
python rbac_report.py .\output\report.json --filter direct
```

**Use case:** See what's configured specifically on resources in the resource group.

---

### `--filter inherited`
Shows **only inherited assignments** from parent scopes (subscription, resource group, management groups).

```bash
python rbac_report.py .\output\report.json --filter inherited
```

**Use case:** Understand what access cascades down from higher scopes.

## Example Workflow

### Generate comprehensive security posture review with inherited assignments:

```powershell
# First, generate RBAC data WITH inherited assignments
./Get-ResourceGroupRbac.ps1 -ResourceGroupName "<RESOURCE_GROUP_NAME>" -SubscriptionId "<SUBSCRIPTION_ID>" -IncludeInherited -ListMembers

# Then generate reports with different filters
python .\rbac_report.py .\output\rbac-<RESOURCE_GROUP_NAME>-*.json --filter all --output-dir .\reports-all
python .\rbac_report.py .\output\rbac-<RESOURCE_GROUP_NAME>-*.json --filter inherited --output-dir .\reports-inherited
```

## Output Files

Each filter generates two files:
- **Markdown**: `rbac_report[-FILTER].md`
- **HTML**: `rbac_report[-FILTER].html`

Examples:
- `rbac_report.md` / `rbac_report.html` (all filter, no suffix)
- `rbac_report-direct.md` / `rbac_report-direct.html`
- `rbac_report-inherited.md` / `rbac_report-inherited.html`

## Report Information

Each report includes:
- **Filter type** in the summary section
- **Total assignments** for that specific filter
- **Risk categorization** (High/Medium/Standard)
- **Assignment details** with scope and inheritance information

## Important Notes

1. **Data source matters:** 
   - If your JSON was generated **without** `-IncludeInherited`, filtering by "inherited" will return 0 results
   - If your JSON was generated **with** `-IncludeInherited`, you'll see inherited assignments and can filter them

2. **For security posture review:**
   - Generate JSON with `-IncludeInherited` flag to capture all access paths
   - Use `--filter inherited` to identify subscription/management-group level access
   - Look for high-risk roles like "User Access Administrator" or "Owner"

3. **For day-to-day resource governance:**
   - Generate JSON without `-IncludeInherited` flag
   - Use `--filter direct` or `--filter all` to see what's directly assigned
