#!/usr/bin/env python3
"""
Demo Data Extension for LimaCharlie

A LimaCharlie extension that:
- Creates a webhook sensor on subscription
- Deploys D&R rules for demo detections
- Provides actions to load demo event data
- Cleans up on unsubscription

Environment Variables:
    EXT_SECRET: Shared secret for extension authentication (required)
    PORT: Port to listen on (default: 8080)
"""

import os
import hashlib
import yaml
from typing import Dict, Any, Optional

from lcextension import Extension
from lcextension.schema import (
    SchemaObject,
    SchemaElement,
    SchemaDataTypes,
    RequestSchema,
    RequestSchemas,
)

# Import core functions from the existing template processor
from log_template_processor import (
    fetch_template,
    process_template,
    send_json_events_to_webhook,
)

# Extension configuration
EXTENSION_NAME = "ext-demo-data"
WEBHOOK_NAME = "demo-data-webhook"
DR_RULE_PREFIX = "demo-"

# Default template URL (hosted on GitHub)
DEFAULT_TEMPLATE_URL = "https://raw.githubusercontent.com/lc-cbot/demo-data-extension/main/lc_events_simple_template.json"

# D&R Rules to deploy (embedded for reliability)
DR_RULES = [
    {
        "name": "demo-encoded-powershell",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "-enc"},
                {"op": "ends with", "path": "event/FILE_PATH", "value": "powershell.exe", "case sensitive": False}
            ]
        },
        "respond": [{"action": "report", "name": "Encoded PowerShell Execution Detected"}]
    },
    {
        "name": "demo-recon-whoami",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "whoami"}
            ]
        },
        "respond": [{"action": "report", "name": "Reconnaissance - whoami Command"}]
    },
    {
        "name": "demo-recon-net-user",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "matches", "path": "event/COMMAND_LINE", "re": r"net\s+(user|group|localgroup).*\/domain", "case sensitive": False}
            ]
        },
        "respond": [{"action": "report", "name": "Domain User Enumeration"}]
    },
    {
        "name": "demo-certutil-download",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "ends with", "path": "event/FILE_PATH", "value": "certutil.exe", "case sensitive": False},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "urlcache"}
            ]
        },
        "respond": [{"action": "report", "name": "Certutil Used for Download"}]
    },
    {
        "name": "demo-mimikatz",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "or", "rules": [
                    {"op": "contains", "path": "event/COMMAND_LINE", "value": "mimikatz", "case sensitive": False},
                    {"op": "contains", "path": "event/COMMAND_LINE", "value": "sekurlsa"},
                    {"op": "contains", "path": "event/FILE_PATH", "value": "mimikatz", "case sensitive": False}
                ]}
            ]
        },
        "respond": [{"action": "report", "name": "Mimikatz Credential Dumping Tool"}]
    },
    {
        "name": "demo-registry-persistence",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "ends with", "path": "event/FILE_PATH", "value": "reg.exe", "case sensitive": False},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "CurrentVersion\\Run", "case sensitive": False}
            ]
        },
        "respond": [{"action": "report", "name": "Registry Run Key Persistence"}]
    },
    {
        "name": "demo-schtasks-persistence",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "NEW_PROCESS"},
                {"op": "ends with", "path": "event/FILE_PATH", "value": "schtasks.exe", "case sensitive": False},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "/create"}
            ]
        },
        "respond": [{"action": "report", "name": "Scheduled Task Created for Persistence"}]
    },
    {
        "name": "demo-failed-login",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "WEL"},
                {"op": "is", "path": "event/EVENT/System/EventID", "value": "4625"}
            ]
        },
        "respond": [{"action": "report", "name": "Windows Failed Login Attempt"}]
    },
    {
        "name": "demo-suspicious-dns",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "DNS_REQUEST"},
                {"op": "contains", "path": "event/DOMAIN_NAME", "value": "malicious"}
            ]
        },
        "respond": [{"action": "report", "name": "Suspicious DNS Request"}]
    },
    {
        "name": "demo-file-public-folder",
        "detect": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "event/_event_type", "value": "FILE_CREATE"},
                {"op": "contains", "path": "event/FILE_PATH", "value": "\\Users\\Public\\", "case sensitive": False},
                {"op": "ends with", "path": "event/FILE_PATH", "value": ".exe", "case sensitive": False}
            ]
        },
        "respond": [{"action": "report", "name": "Executable Created in Public Folder"}]
    },
]


def generate_webhook_secret(oid: str) -> str:
    """Generate a deterministic webhook secret based on OID."""
    secret_base = f"{EXTENSION_NAME}-webhook-secret:{oid}"
    return hashlib.sha256(secret_base.encode()).hexdigest()[:32]


def get_webhook_url(oid: str, hook_domain: str) -> str:
    """Construct the full webhook URL for an organization."""
    secret = generate_webhook_secret(oid)
    return f"https://{hook_domain}/{oid}/{WEBHOOK_NAME}/{secret}"


class DemoDataExtension(Extension):
    """LimaCharlie Extension for Demo Data Loading."""

    def __init__(self):
        secret = os.environ.get("EXT_SECRET")
        if not secret:
            raise ValueError("EXT_SECRET environment variable is required")

        super().__init__(EXTENSION_NAME, secret)

        # Register event handlers
        self.eventHandlers["subscribe"] = self._on_subscribe
        self.eventHandlers["unsubscribe"] = self._on_unsubscribe

        # Register request handlers (actions)
        self.requestHandlers["load_demo_data"] = self._load_demo_data
        self.requestHandlers["get_webhook_url"] = self._get_webhook_url
        self.requestHandlers["get_status"] = self._get_status

    def getSchema(self) -> Dict[str, Any]:
        """Define the extension schema for UI and configuration."""
        return {
            "config_schema": SchemaObject(
                fields={
                    "auto_load_on_subscribe": SchemaElement(
                        label="Auto-load demo data on subscribe",
                        data_type=SchemaDataTypes.Boolean,
                        default_value=True,
                        description="Automatically load demo events when an organization subscribes"
                    ),
                    "template_url": SchemaElement(
                        label="Event Template URL",
                        data_type=SchemaDataTypes.String,
                        default_value=DEFAULT_TEMPLATE_URL,
                        description="URL to fetch the JSON event template from"
                    ),
                },
                description="Demo Data Extension Configuration"
            ).asDict(),
            "request_schema": RequestSchemas(
                schemas={
                    "load_demo_data": RequestSchema(
                        label="Load Demo Data",
                        description="Load demo security events into the organization",
                        parameters=SchemaObject(
                            fields={
                                "template_url": SchemaElement(
                                    label="Template URL (optional)",
                                    data_type=SchemaDataTypes.String,
                                    is_required=False,
                                    description="Override the default template URL"
                                ),
                            }
                        ),
                    ),
                    "get_webhook_url": RequestSchema(
                        label="Get Webhook URL",
                        description="Get the webhook URL for sending custom events",
                        parameters=SchemaObject(fields={}),
                    ),
                    "get_status": RequestSchema(
                        label="Get Status",
                        description="Get the current status of the extension for this organization",
                        parameters=SchemaObject(fields={}),
                    ),
                }
            ).asDict(),
            "required_events": ["subscribe", "unsubscribe"],
        }

    def _on_subscribe(self, sdk, data: Dict, conf: Dict) -> Dict[str, Any]:
        """Handle organization subscription."""
        oid = sdk._oid
        results = {
            "webhook_created": False,
            "rules_deployed": 0,
            "demo_data_loaded": False,
            "errors": [],
        }

        try:
            # Step 1: Create webhook sensor using extension adapter helper
            webhook_secret = generate_webhook_secret(oid)
            try:
                self.create_extension_adapter(
                    sdk,
                    WEBHOOK_NAME,
                    webhook_secret,
                    "json",  # platform
                )
                results["webhook_created"] = True
            except Exception as e:
                # Webhook might already exist
                if "already exists" in str(e).lower():
                    results["webhook_created"] = True
                else:
                    results["errors"].append(f"Webhook creation failed: {str(e)}")

            # Step 2: Deploy D&R rules
            for rule in DR_RULES:
                try:
                    sdk.rules().set(
                        rule["name"],
                        {
                            "detect": rule["detect"],
                            "respond": rule["respond"],
                        },
                        namespace="managed",
                        tags=["demo-data-extension"],
                    )
                    results["rules_deployed"] += 1
                except Exception as e:
                    results["errors"].append(f"Rule {rule['name']} failed: {str(e)}")

            # Step 3: Auto-load demo data if configured
            auto_load = conf.get("auto_load_on_subscribe", True)
            if auto_load and results["webhook_created"]:
                try:
                    template_url = conf.get("template_url", DEFAULT_TEMPLATE_URL)
                    hook_domain = sdk._lc._api.getHookDomain()
                    webhook_url = get_webhook_url(oid, hook_domain)

                    load_result = self._do_load_demo_data(template_url, webhook_url)
                    if load_result.get("events_failed", 0) == 0:
                        results["demo_data_loaded"] = True
                    else:
                        results["errors"].append(f"Some events failed to load: {load_result}")
                except Exception as e:
                    results["errors"].append(f"Demo data loading failed: {str(e)}")

        except Exception as e:
            results["errors"].append(f"Subscription handler error: {str(e)}")

        return {"data": results}

    def _on_unsubscribe(self, sdk, data: Dict, conf: Dict) -> Dict[str, Any]:
        """Handle organization unsubscription."""
        results = {
            "webhook_deleted": False,
            "rules_deleted": 0,
            "errors": [],
        }

        try:
            # Step 1: Delete webhook sensor
            try:
                self.delete_extension_adapter(sdk, WEBHOOK_NAME)
                results["webhook_deleted"] = True
            except Exception as e:
                if "not found" in str(e).lower():
                    results["webhook_deleted"] = True
                else:
                    results["errors"].append(f"Webhook deletion failed: {str(e)}")

            # Step 2: Delete D&R rules
            for rule in DR_RULES:
                try:
                    sdk.rules().delete(rule["name"], namespace="managed")
                    results["rules_deleted"] += 1
                except Exception as e:
                    if "not found" in str(e).lower():
                        results["rules_deleted"] += 1
                    else:
                        results["errors"].append(f"Rule {rule['name']} deletion failed: {str(e)}")

        except Exception as e:
            results["errors"].append(f"Unsubscription handler error: {str(e)}")

        return {"data": results}

    def _load_demo_data(self, sdk, data: Dict, conf: Dict) -> Dict[str, Any]:
        """Action: Load demo data into the organization."""
        oid = sdk._oid

        # Get template URL from request or config
        template_url = data.get("template_url") or conf.get("template_url", DEFAULT_TEMPLATE_URL)

        try:
            # Get webhook URL
            hook_domain = sdk._lc._api.getHookDomain()
            webhook_url = get_webhook_url(oid, hook_domain)

            # Load the demo data
            result = self._do_load_demo_data(template_url, webhook_url)
            return {"data": result}

        except Exception as e:
            return {"error": f"Failed to load demo data: {str(e)}"}

    def _do_load_demo_data(self, template_url: str, webhook_url: str) -> Dict[str, Any]:
        """Internal method to load demo data."""
        # Fetch and process the template
        template_content = fetch_template(template_url)
        events = process_template(template_content)

        if not isinstance(events, list):
            raise ValueError("Template must produce a list of events")

        # Send to webhook
        successful, failed = send_json_events_to_webhook(webhook_url, events)

        return {
            "status": "success" if failed == 0 else "partial",
            "template_url": template_url,
            "events_total": len(events),
            "events_sent": successful,
            "events_failed": failed,
        }

    def _get_webhook_url(self, sdk, data: Dict, conf: Dict) -> Dict[str, Any]:
        """Action: Get the webhook URL for this organization."""
        oid = sdk._oid

        try:
            hook_domain = sdk._lc._api.getHookDomain()
            webhook_url = get_webhook_url(oid, hook_domain)

            return {
                "data": {
                    "webhook_url": webhook_url,
                    "webhook_name": WEBHOOK_NAME,
                    "usage": "POST flat JSON events to this URL",
                }
            }
        except Exception as e:
            return {"error": f"Failed to get webhook URL: {str(e)}"}

    def _get_status(self, sdk, data: Dict, conf: Dict) -> Dict[str, Any]:
        """Action: Get extension status for this organization."""
        oid = sdk._oid
        status = {
            "webhook_exists": False,
            "webhook_name": WEBHOOK_NAME,
            "rules_deployed": [],
            "rules_missing": [],
        }

        try:
            # Check webhook
            try:
                sensors = sdk.sensors()
                for sensor in sensors:
                    if sensor.get("hostname") == WEBHOOK_NAME:
                        status["webhook_exists"] = True
                        break
            except Exception:
                pass

            # Check D&R rules
            try:
                existing_rules = sdk.rules().get(namespace="managed")
                existing_names = set(existing_rules.keys()) if existing_rules else set()

                for rule in DR_RULES:
                    if rule["name"] in existing_names:
                        status["rules_deployed"].append(rule["name"])
                    else:
                        status["rules_missing"].append(rule["name"])
            except Exception as e:
                status["rules_error"] = str(e)

            # Add webhook URL
            try:
                hook_domain = sdk._lc._api.getHookDomain()
                status["webhook_url"] = get_webhook_url(oid, hook_domain)
            except Exception:
                pass

            return {"data": status}

        except Exception as e:
            return {"error": f"Failed to get status: {str(e)}"}


# Create extension instance
ext = DemoDataExtension()

# Get the Flask app for deployment
app = ext.app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
