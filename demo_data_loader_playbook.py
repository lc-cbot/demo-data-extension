"""
Demo Data Loader Playbook for LimaCharlie

Fetches a JSON event template from a URL, fills in recent dates using Jinja2,
and sends flat JSON events to a webhook for D&R rule testing.

Usage via D&R rule:
  - action: extension request
    extension name: ext-playbook
    extension action: run_playbook
    extension request:
      name: demo-data-loader
      data:
        template_url: "https://storage.googleapis.com/.../demo_events_template.json"
        webhook_url: "https://[hook].hook.limacharlie.io/[oid]/[name]/[secret]"

Or pass webhook as hive reference:
      data:
        template_url: "https://..."
        webhook: "hive://secret/demo-webhook-url"
"""

import json
import time
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from jinja2 import Environment, BaseLoader


def get_past_week_dates():
    """Generate list of dates for the past 7 days (including today)."""
    today = datetime.now().date()
    return [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]


def format_syslog_date(date_obj):
    """Format date in BSD syslog style: 'Mon DD' with space-padded day."""
    month = date_obj.strftime("%b")
    day = date_obj.day
    return f"{month} {day:2d}"


def distribute_dates(num_items, dates):
    """Distribute dates across items to spread events over 7 days."""
    if num_items == 0:
        return []
    return [dates[(i * len(dates)) // num_items] for i in range(num_items)]


def render_template_in_value(value, template_vars, env):
    """Recursively render Jinja2 templates in JSON values."""
    if isinstance(value, str):
        if '{{' in value and '}}' in value:
            try:
                template = env.from_string(value)
                return template.render(**template_vars)
            except Exception:
                return value
        return value
    elif isinstance(value, dict):
        return {k: render_template_in_value(v, template_vars, env) for k, v in value.items()}
    elif isinstance(value, list):
        return [render_template_in_value(item, template_vars, env) for item in value]
    else:
        return value


def fetch_template(url):
    """Fetch template content from a URL."""
    with urlopen(url, timeout=30) as response:
        return response.read().decode('utf-8')


def process_json_template(template_content):
    """Process a JSON array template, filling in dates spread over 7 days."""
    events = json.loads(template_content.strip())

    if not isinstance(events, list):
        raise ValueError("JSON template must be an array of events")

    dates = get_past_week_dates()
    date_assignments = distribute_dates(len(events), dates)
    env = Environment(loader=BaseLoader())

    processed_events = []
    for event, assigned_date in zip(events, date_assignments):
        date_obj = datetime.strptime(assigned_date, "%Y-%m-%d")
        days_ago = (datetime.now().date() - date_obj.date()).days

        template_vars = {
            'date': assigned_date,
            'date_us': date_obj.strftime("%m/%d/%Y"),
            'date_eu': date_obj.strftime("%d/%m/%Y"),
            'date_short': date_obj.strftime("%Y%m%d"),
            'syslog_date': format_syslog_date(date_obj),
            'day_offset': days_ago,
        }

        processed_event = render_template_in_value(event, template_vars, env)
        processed_events.append(processed_event)

    return processed_events


def send_events_to_webhook(webhook_url, events, delay=0.05):
    """Send events to webhook as flat JSON objects."""
    successful = 0
    failed = 0
    errors = []

    for i, event in enumerate(events):
        try:
            json_data = json.dumps(event).encode('utf-8')
            request = Request(
                webhook_url,
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'LC-DemoDataLoader/1.0'
                },
                method='POST'
            )

            with urlopen(request, timeout=30) as response:
                if 200 <= response.getcode() < 300:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"Event {i+1}: HTTP {response.getcode()}")

        except (HTTPError, URLError) as e:
            failed += 1
            errors.append(f"Event {i+1}: {str(e)}")
        except Exception as e:
            failed += 1
            errors.append(f"Event {i+1}: {str(e)}")

        if delay > 0:
            time.sleep(delay)

    return successful, failed, errors


def playbook(sdk, data):
    """
    Main playbook entry point.

    Args:
        sdk: LimaCharlie SDK instance (can be None)
        data: Dictionary containing request object with nested 'data' key:
            - data.data.template_url: URL to fetch JSON event template from
            - data.data.webhook_url: Webhook URL to send events to
            - data.data.webhook: Optional hive reference like "hive://secret/webhook-secret"
            - data.data.delay: Optional delay between events in seconds (default: 0.05)

    Returns:
        Dictionary with 'data' (success info) or 'error' (failure message)
    """
    import limacharlie

    # Validate required parameters
    if not data:
        return {"error": "No data provided. Required: template_url, webhook_url"}

    # The playbook receives the full request object with keys: data, name
    # The actual parameters are in data['data']
    params = data.get('data', data)  # Fall back to data itself if no nested data
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except:
            return {"error": "Data is string but not valid JSON"}

    template_url = params.get('template_url')
    if not template_url:
        return {"error": "Missing required parameter: template_url"}

    # Get webhook URL - either direct or from hive secret
    webhook_url = params.get('webhook_url')
    webhook_ref = params.get('webhook')

    if not webhook_url and not webhook_ref:
        return {"error": "Missing required parameter: webhook_url or webhook (hive reference)"}

    # If webhook is a hive reference, resolve it
    if webhook_ref and not webhook_url:
        if not sdk:
            return {"error": "SDK required to resolve hive reference for webhook"}
        try:
            # Parse hive reference: hive://secret/secret-name
            if webhook_ref.startswith("hive://secret/"):
                secret_name = webhook_ref.replace("hive://secret/", "")
                hive = limacharlie.Hive(sdk, "secret")
                secret_data = hive.get(secret_name)
                webhook_url = secret_data.data.get("secret")
                if not webhook_url:
                    return {"error": f"Secret '{secret_name}' does not contain 'secret' key"}
            else:
                return {"error": f"Invalid hive reference format: {webhook_ref}"}
        except Exception as e:
            return {"error": f"Failed to resolve webhook from hive: {str(e)}"}

    delay = params.get('delay', 0.05)

    try:
        # Fetch template
        template_content = fetch_template(template_url)

        # Process template (fill in dates)
        events = process_json_template(template_content)

        # Send to webhook
        successful, failed, errors = send_events_to_webhook(webhook_url, events, delay)

        result = {
            "status": "success" if failed == 0 else "partial",
            "template_url": template_url,
            "events_total": len(events),
            "events_sent": successful,
            "events_failed": failed,
        }

        if errors:
            result["errors"] = errors[:10]  # Limit error messages
            if len(errors) > 10:
                result["errors_truncated"] = len(errors) - 10

        if failed > 0:
            return {
                "data": result,
                "error": f"Partial failure: {failed}/{len(events)} events failed"
            }

        return {"data": result}

    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON in template: {str(e)}"}
    except (HTTPError, URLError) as e:
        return {"error": f"Failed to fetch template: {str(e)}"}
    except Exception as e:
        return {"error": f"Playbook execution failed: {str(e)}"}
