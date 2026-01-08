# Demo Data Loader System Documentation

This document describes the demo data loading system for LimaCharlie, which generates sample security events with recent timestamps and sends them to webhooks for D&R rule testing.

## Table of Contents

1. [Overview](#overview)
2. [Components](#components)
3. [How It Works](#how-it-works)
4. [Event Template Format](#event-template-format)
5. [D&R Rules for Webhook Events](#dr-rules-for-webhook-events)
6. [Usage](#usage)
7. [Maintenance](#maintenance)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### Purpose

This system solves the problem of generating realistic sample security data for demo organizations. When a new LimaCharlie organization is created:

1. Infrastructure as Code (IaC) loads D&R rules
2. A playbook fires to load sample event data
3. Events are sent to a webhook with recent timestamps
4. D&R rules trigger, generating alerts for demonstration

### Key Design Decision: Flat JSON Events

**Critical**: Webhook events must be sent as **flat JSON objects** (not wrapped in an `events` array) for D&R rules to work correctly.

| Format | D&R Path | Works? |
|--------|----------|--------|
| `{"events": [{...}]}` | `event/events/0/COMMAND_LINE` | No |
| `{...}` (flat) | `event/COMMAND_LINE` | Yes |

---

## Components

### 1. Log Template Processor (`log_template_processor.py`)

A standalone Python script that:
- Fetches JSON event templates from URLs or local files
- Fills in date placeholders using Jinja2 templating
- Distributes events across the past 7 days
- Sends events to webhooks as flat JSON

**Location**: `/home/chrisbotelho/lc-ai-components/log_template_processor.py`

### 2. Demo Events Template (`demo_events_template.json`)

A JSON array of 15 security events designed to trigger common detections:
- Encoded PowerShell execution
- Reconnaissance commands (whoami, net user)
- Certutil download (LOLBin)
- Mimikatz credential dumping
- Registry persistence
- Scheduled task persistence
- Failed login brute force (5x Event ID 4625)
- Suspicious DNS requests
- File creation in Public folder

**Location**: `/home/chrisbotelho/lc-ai-components/demo_events_template.json`

### 3. Demo D&R Rules (`demo_dr_rules.yaml`)

10 detection rules that match the demo events:
- `demo-encoded-powershell`
- `demo-recon-whoami`
- `demo-recon-net-user`
- `demo-certutil-download`
- `demo-mimikatz`
- `demo-registry-persistence`
- `demo-schtasks-persistence`
- `demo-failed-login`
- `demo-suspicious-dns`
- `demo-file-public-folder`

**Location**: `/home/chrisbotelho/lc-ai-components/demo_dr_rules.yaml`

### 4. LimaCharlie Playbook (`demo-data-loader`)

A Python playbook deployed to LimaCharlie that replicates the log_template_processor functionality within the LimaCharlie execution environment.

**Deployed to**: TPS Reporting Solutions (`aac9c41d-e0a3-4e7e-88b8-33936ab93238`)

**Local copy**: `/home/chrisbotelho/lc-ai-components/demo_data_loader_playbook.py`

---

## How It Works

### Event Flow

```
┌─────────────────────┐
│  JSON Template      │  Contains events with {{ date }} placeholders
│  (URL or file)      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Template Processor │  1. Fetches template
│  (Script/Playbook)  │  2. Fills in dates (spread over 7 days)
│                     │  3. Renders Jinja2 variables
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Webhook Sensor     │  Receives flat JSON via HTTP POST
│  (LimaCharlie)      │  Creates events with routing metadata
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  D&R Rules          │  Match on event/FIELD_NAME paths
│  (LimaCharlie)      │  Generate detections/alerts
└─────────────────────┘
```

### Date Distribution

Events are distributed across 7 days to simulate realistic activity:

```
Template with 15 events:
├── Events 1-2:   Today (2026-01-06)
├── Events 3-4:   Yesterday (2026-01-05)
├── Events 5-6:   2 days ago
├── Events 7-8:   3 days ago
├── Events 9-10:  4 days ago
├── Events 11-12: 5 days ago
└── Events 13-15: 6 days ago
```

### Template Variables

| Variable | Format | Example |
|----------|--------|---------|
| `{{ date }}` | YYYY-MM-DD | 2026-01-06 |
| `{{ date_us }}` | MM/DD/YYYY | 01/06/2026 |
| `{{ date_eu }}` | DD/MM/YYYY | 06/01/2026 |
| `{{ date_short }}` | YYYYMMDD | 20260106 |
| `{{ syslog_date }}` | Mon DD | Jan  6 |
| `{{ day_offset }}` | Integer | 0 (today), 1 (yesterday), etc. |

---

## Event Template Format

### Structure

Events must be a JSON array of flat objects:

```json
[
  {
    "_event_type": "NEW_PROCESS",
    "_ts": "{{ date }} 10:15:32",
    "COMMAND_LINE": "powershell.exe -enc SGVsbG8=",
    "FILE_PATH": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "PROCESS_ID": 6234,
    "USER_NAME": "CORP\\jsmith"
  },
  {
    "_event_type": "DNS_REQUEST",
    "_ts": "{{ date }} 10:20:05",
    "DOMAIN_NAME": "c2.malicious-domain.com",
    "PROCESS_ID": 6234
  }
]
```

### Required Fields

- `_event_type`: Custom field to identify event type (used in D&R rules)
- `_ts`: Timestamp with Jinja2 date placeholder

### Supported Event Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `NEW_PROCESS` | Process creation | COMMAND_LINE, FILE_PATH, PROCESS_ID, USER_NAME, PARENT |
| `NETWORK_CONNECTIONS` | Network activity | NETWORK_ACTIVITY (array), PROCESS_ID |
| `DNS_REQUEST` | DNS lookup | DOMAIN_NAME, DNS_TYPE |
| `FILE_CREATE` | File creation | FILE_PATH, HASH |
| `WEL` | Windows Event Log | EVENT.System.EventID, EVENT.EventData.* |

### Windows Event Log Format

```json
{
  "_event_type": "WEL",
  "_ts": "{{ date }} 08:30:15",
  "EVENT": {
    "EventData": {
      "TargetUserName": "Administrator",
      "IpAddress": "192.168.1.100",
      "LogonType": "3",
      "Status": "0xc000006d"
    },
    "System": {
      "EventID": "4625",
      "Computer": "DC01.corp.local",
      "TimeCreated": {
        "SystemTime": "{{ date }}T08:30:15.000Z"
      }
    }
  }
}
```

---

## D&R Rules for Webhook Events

### Path Structure

Webhook events have their data at `event/<field>`:

```yaml
detect:
  op: contains
  path: event/COMMAND_LINE      # NOT event/events/0/COMMAND_LINE
  value: "-enc"
```

### Example Rules

**Encoded PowerShell:**
```yaml
name: demo-encoded-powershell
detect:
  op: and
  rules:
    - op: is
      path: event/_event_type
      value: NEW_PROCESS
    - op: contains
      path: event/COMMAND_LINE
      value: -enc
    - op: ends with
      path: event/FILE_PATH
      value: powershell.exe
      case sensitive: false
respond:
  - action: report
    name: Encoded PowerShell Execution Detected
```

**Windows Failed Login:**
```yaml
name: demo-failed-login
detect:
  op: and
  rules:
    - op: is
      path: event/_event_type
      value: WEL
    - op: is
      path: event/EVENT/System/EventID
      value: "4625"
respond:
  - action: report
    name: Windows Failed Login Attempt
```

---

## Usage

### Method 1: Standalone Script

```bash
# Output to file
python3 log_template_processor.py template.json output.json

# Send to webhook
python3 log_template_processor.py template.json "https://[hook].hook.limacharlie.io/..."

# Fetch from URL and send to webhook
python3 log_template_processor.py "https://example.com/template.json" "https://webhook.url"
```

### Method 2: LimaCharlie Playbook

**Via Python SDK:**
```python
import limacharlie

lc = limacharlie.Manager(oid="your-org-id")
ext = limacharlie.Extension(lc)

response = ext.request("ext-playbook", "run_playbook", {
    "name": "demo-data-loader",
    "data": {
        "template_url": "https://storage.googleapis.com/.../template.json",
        "webhook_url": "https://[hook].hook.limacharlie.io/[oid]/[name]/[secret]"
    }
})

print(response)
# {'data': {'status': 'success', 'events_total': 50, 'events_sent': 50, ...}}
```

**Via D&R Rule (triggered by another event):**
```yaml
respond:
  - action: extension request
    extension name: ext-playbook
    extension action: run_playbook
    extension request:
      name: demo-data-loader
      data:
        template_url: "https://..."
        webhook_url: "https://..."
```

**Using Hive Secret for Webhook URL:**
```python
# Store webhook URL as a secret first
# Then reference it in playbook call:
ext.request("ext-playbook", "run_playbook", {
    "name": "demo-data-loader",
    "data": {
        "template_url": "https://...",
        "webhook": "hive://secret/demo-webhook-url"  # Secret reference
    }
})
```

### Method 3: Infrastructure as Code

Include in your IaC configuration:

```yaml
hives:
  playbook:
    demo-data-loader:
      data:
        python: |
          # ... playbook code from demo_data_loader_playbook.py ...
      usr_mtd:
        enabled: true
        tags: ["demo", "data-loader"]
        comment: "Loads demo event data for D&R testing"
```

---

## Maintenance

### Adding New Event Types

1. **Add to template** (`demo_events_template.json`):
```json
{
  "_event_type": "NEW_EVENT_TYPE",
  "_ts": "{{ date }} 12:00:00",
  "FIELD1": "value1",
  "FIELD2": "value2"
}
```

2. **Create matching D&R rule** (`demo_dr_rules.yaml`):
```yaml
name: demo-new-detection
detect:
  op: and
  rules:
    - op: is
      path: event/_event_type
      value: NEW_EVENT_TYPE
    - op: contains
      path: event/FIELD1
      value: suspicious
respond:
  - action: report
    name: New Detection Triggered
```

3. **Test the rule**:
```bash
python3 log_template_processor.py demo_events_template.json "https://webhook.url"
```

### Updating the Playbook

1. **Edit local file**: `demo_data_loader_playbook.py`

2. **Deploy to LimaCharlie**:
```python
import limacharlie

lc = limacharlie.Manager(oid="aac9c41d-e0a3-4e7e-88b8-33936ab93238")

# Read updated playbook code
with open("demo_data_loader_playbook.py", "r") as f:
    code = f.read()

# Extract just the code (skip docstring at top)
# The playbook code starts after the module docstring

hive = limacharlie.Hive(lc, "playbook")
hive.set("demo-data-loader", {
    "python": code
})
```

Or use the MCP tool:
```
set_playbook(oid, "demo-data-loader", {"python": "..."})
```

### Uploading Templates to Cloud Storage

For production use, upload templates to a publicly accessible location:

```bash
# Google Cloud Storage example
gsutil cp demo_events_template.json gs://your-bucket/templates/
gsutil acl ch -u AllUsers:R gs://your-bucket/templates/demo_events_template.json
```

### Adding New Template Variables

1. **Edit `log_template_processor.py`** in `process_json_template()`:
```python
template_vars = {
    'date': assigned_date,
    # ... existing vars ...
    'new_var': compute_new_value(date_obj),  # Add here
}
```

2. **Update playbook** with same change

3. **Use in templates**:
```json
{"field": "{{ new_var }}"}
```

---

## Troubleshooting

### Events Not Triggering D&R Rules

**Symptom**: Events are ingested but rules don't fire.

**Check**:
1. Verify D&R rule paths use `event/FIELD_NAME` (not `event/events/0/...`)
2. Check webhook is sending flat JSON (not wrapped in `{"events": [...]}`)
3. Test rule with `test_dr_rule_events` API:

```python
lc_call_tool("test_dr_rule_events", {
    "oid": "...",
    "detect": {"op": "contains", "path": "event/COMMAND_LINE", "value": "-enc"},
    "events": [{
        "routing": {"event_type": "json"},
        "event": {"COMMAND_LINE": "powershell -enc ABC", "_event_type": "NEW_PROCESS"}
    }],
    "trace": true
})
```

### Playbook Returns "Missing required parameter"

**Symptom**: Playbook executes but returns error about missing parameters.

**Cause**: The playbook receives parameters nested in `data['data']`, not directly in `data`.

**Fix**: Ensure playbook extracts params correctly:
```python
params = data.get('data', data)  # Get nested data or fall back to data
template_url = params.get('template_url')
```

### Webhook Returns HTTP Errors

**Symptom**: Script/playbook reports failed events.

**Check**:
1. Webhook URL is correct and active
2. Webhook sensor exists in the organization
3. Secret in webhook URL is valid
4. Organization has ext-webhook extension enabled

### Date Placeholders Not Replaced

**Symptom**: Events contain literal `{{ date }}` strings.

**Check**:
1. Template is valid JSON array
2. Jinja2 is installed (`pip install jinja2`)
3. Placeholders use correct syntax: `{{ date }}` (spaces inside braces)

---

## File Locations Summary

All files are located in: `lc-ai-components/demo-data-loader/`

| File | Purpose |
|------|---------|
| `log_template_processor.py` | Standalone CLI tool |
| `demo_events_template.json` | 15 detection-triggering events |
| `demo_dr_rules.yaml` | 10 matching D&R rules |
| `demo_data_loader_playbook.py` | Local copy of playbook source |
| `lc_events_template.json` | 50-event template (full LC event format) |
| `lc_events_simple_template.json` | 50-event simplified template |
| `DEMO_DATA_LOADER_DOCUMENTATION.md` | This documentation |

---

## Version History

| Date | Change |
|------|--------|
| 2026-01-06 | Initial creation of demo data loader system |
| 2026-01-06 | Fixed webhook format to use flat JSON (not wrapped in events array) |
| 2026-01-06 | Created and deployed demo-data-loader playbook to TPS Reporting Solutions |
| 2026-01-06 | Tested end-to-end: 50 events sent successfully |

---

## Contact

For questions about this system, refer to:
- LimaCharlie Documentation: https://docs.limacharlie.io
- Playbook Extension: https://docs.limacharlie.io/docs/playbook
- D&R Rules: https://docs.limacharlie.io/docs/detection-and-response
