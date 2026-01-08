#!/usr/bin/env python3
"""
Log Template Processor

Processes a Jinja2-templatized log file and fills in date values.
Dates are spread across the past 7 days while preserving original times.

Usage:
    python log_template_processor.py <template_source> [output_destination]

The template_source can be either:
    - A local file path (e.g., fortigate_template.log)
    - A URL (e.g., https://example.com/template.log)

The output_destination can be:
    - A local file path (e.g., output.log)
    - A webhook URL (e.g., https://example.com/webhook) - sends JSON POST requests
    - Omitted - prints to stdout

Examples:
    # Output to file
    python log_template_processor.py fortigate_template.log fortigate_output.log

    # Output to webhook
    python log_template_processor.py https://storage.googleapis.com/template.log https://webhook.example.com/endpoint

    # Output to stdout
    python log_template_processor.py fortigate_template.log

Supported template variables:
    {{ date }}         - YYYY-MM-DD format (e.g., 2025-01-06)
    {{ date_us }}      - MM/DD/YYYY format (e.g., 01/06/2025)
    {{ date_eu }}      - DD/MM/YYYY format (e.g., 06/01/2025)
    {{ date_short }}   - YYYYMMDD format (e.g., 20250106)
    {{ syslog_date }}  - BSD syslog format (e.g., Jan  6 or Jan 15)
    {{ day_offset }}   - Number of days ago (0-6)
"""

import sys
import json
import time
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from jinja2 import Environment, BaseLoader


def is_url(source):
    """Check if the source is a URL."""
    return source.startswith('http://') or source.startswith('https://')


def fetch_template(source):
    """
    Fetch template content from a URL or local file.

    Args:
        source: URL or local file path

    Returns:
        Template content as string

    Raises:
        SystemExit on error
    """
    if is_url(source):
        try:
            print(f"Fetching template from URL: {source}", file=sys.stderr)
            with urlopen(source, timeout=30) as response:
                content = response.read().decode('utf-8')
            print(f"Successfully fetched {len(content)} bytes", file=sys.stderr)
            return content
        except HTTPError as e:
            print(f"Error: HTTP {e.code} when fetching URL: {source}", file=sys.stderr)
            sys.exit(1)
        except URLError as e:
            print(f"Error: Failed to fetch URL: {e.reason}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error fetching URL: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            with open(source, 'r') as f:
                return f.read()
        except FileNotFoundError:
            print(f"Error: Template file '{source}' not found.", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error reading template file: {e}", file=sys.stderr)
            sys.exit(1)


def send_to_webhook(webhook_url, log_lines, batch_size=10, delay_between_batches=0.1):
    """
    Send log lines to a webhook URL as JSON POST requests.

    Args:
        webhook_url: The webhook endpoint URL
        log_lines: List of log line strings to send
        batch_size: Number of events to send per request (default: 10)
        delay_between_batches: Seconds to wait between batches (default: 0.1)

    Returns:
        Tuple of (successful_count, failed_count)
    """
    successful = 0
    failed = 0
    total = len(log_lines)

    print(f"Sending {total} events to webhook: {webhook_url}", file=sys.stderr)

    # Send events in batches
    for i in range(0, total, batch_size):
        batch = log_lines[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (total + batch_size - 1) // batch_size

        # Prepare JSON payload - send as array of event objects
        payload = {
            "events": [{"raw": line} for line in batch]
        }

        try:
            json_data = json.dumps(payload).encode('utf-8')
            request = Request(
                webhook_url,
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'LogTemplateProcessor/1.0'
                },
                method='POST'
            )

            with urlopen(request, timeout=30) as response:
                status = response.getcode()
                if 200 <= status < 300:
                    successful += len(batch)
                    print(f"  Batch {batch_num}/{total_batches}: Sent {len(batch)} events (HTTP {status})", file=sys.stderr)
                else:
                    failed += len(batch)
                    print(f"  Batch {batch_num}/{total_batches}: Failed with HTTP {status}", file=sys.stderr)

        except HTTPError as e:
            failed += len(batch)
            print(f"  Batch {batch_num}/{total_batches}: HTTP error {e.code}: {e.reason}", file=sys.stderr)
        except URLError as e:
            failed += len(batch)
            print(f"  Batch {batch_num}/{total_batches}: URL error: {e.reason}", file=sys.stderr)
        except Exception as e:
            failed += len(batch)
            print(f"  Batch {batch_num}/{total_batches}: Error: {e}", file=sys.stderr)

        # Small delay between batches to avoid overwhelming the webhook
        if i + batch_size < total and delay_between_batches > 0:
            time.sleep(delay_between_batches)

    print(f"Complete: {successful} successful, {failed} failed out of {total} events", file=sys.stderr)
    return successful, failed


def get_past_week_dates():
    """Generate list of dates for the past 7 days (including today)."""
    today = datetime.now().date()
    return [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]


def format_syslog_date(date_obj):
    """
    Format date in BSD syslog style: 'Mon DD' where DD has leading space for single digits.
    Examples: 'Jan  6', 'Jan 15', 'Dec 31'
    """
    month = date_obj.strftime("%b")
    day = date_obj.day
    # BSD syslog uses space-padded day (e.g., "Jan  6" not "Jan 06")
    return f"{month} {day:2d}"


def parse_template_lines(template_content):
    """
    Parse template content and identify lines with date placeholders.
    Returns list of (line, line_index) tuples.
    """
    lines = template_content.strip().split('\n')
    return [(line, idx) for idx, line in enumerate(lines) if line.strip()]


def distribute_dates(num_lines, dates):
    """
    Distribute dates across log lines to spread events over 7 days.
    Returns a list of date strings, one per line.
    """
    if num_lines == 0:
        return []

    # Distribute lines across available dates
    date_assignments = []
    for i in range(num_lines):
        # Map line index to a date index (spreads evenly)
        date_idx = (i * len(dates)) // num_lines
        date_assignments.append(dates[date_idx])

    return date_assignments


def is_json_array(content):
    """Check if the content is a JSON array."""
    stripped = content.strip()
    if not stripped.startswith('['):
        return False
    try:
        json.loads(stripped)
        return True
    except json.JSONDecodeError:
        return False


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


def process_json_template(template_content):
    """
    Process a JSON array template file.

    Each JSON object in the array is treated as a separate event.
    Template variables in string values are replaced with dates spread over 7 days.
    """
    try:
        events = json.loads(template_content.strip())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in template: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(events, list):
        print("Error: JSON template must be an array of events", file=sys.stderr)
        sys.exit(1)

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


def process_template(template_content):
    """
    Process the template file and generate output with dates filled in.

    Supports the following template variables:
    - {{ date }}: Will be replaced with a date from the past 7 days (YYYY-MM-DD)
    - {{ date_us }}: US format date (MM/DD/YYYY)
    - {{ date_eu }}: EU format date (DD/MM/YYYY)
    - {{ date_short }}: Short format (YYYYMMDD)
    - {{ syslog_date }}: BSD syslog format (Mon DD with space-padded day)
    - {{ day_offset }}: Number of days ago (0-6)

    Automatically detects JSON arrays vs line-based logs.
    """
    # Check if this is a JSON array template
    if is_json_array(template_content):
        print("Detected JSON array template", file=sys.stderr)
        return process_json_template(template_content)

    # Line-based log processing
    lines = [line for line in template_content.strip().split('\n') if line.strip()]
    dates = get_past_week_dates()
    date_assignments = distribute_dates(len(lines), dates)

    env = Environment(loader=BaseLoader())
    output_lines = []

    for line, assigned_date in zip(lines, date_assignments):
        # Parse the assigned date
        date_obj = datetime.strptime(assigned_date, "%Y-%m-%d")
        days_ago = (datetime.now().date() - date_obj.date()).days

        # Prepare template variables
        template_vars = {
            'date': assigned_date,
            'date_us': date_obj.strftime("%m/%d/%Y"),
            'date_eu': date_obj.strftime("%d/%m/%Y"),
            'date_short': date_obj.strftime("%Y%m%d"),
            'syslog_date': format_syslog_date(date_obj),
            'day_offset': days_ago,
        }

        try:
            template = env.from_string(line)
            rendered = template.render(**template_vars)
            output_lines.append(rendered)
        except Exception as e:
            # If template parsing fails, keep original line
            print(f"Warning: Failed to process line: {e}", file=sys.stderr)
            output_lines.append(line)

    return '\n'.join(output_lines)


def send_json_events_to_webhook(webhook_url, events, batch_size=1, delay_between_batches=0.05):
    """
    Send JSON events to a webhook URL.

    Each JSON event is sent as a single HTTP request as a FLAT JSON object.
    This ensures D&R rules can access fields at event/FIELD_NAME paths
    (not nested in event/events/0/FIELD_NAME).

    Args:
        webhook_url: The webhook endpoint URL
        events: List of event dictionaries to send
        batch_size: Number of events to send per request (default: 1 for individual events)
        delay_between_batches: Seconds to wait between requests (default: 0.05)

    Returns:
        Tuple of (successful_count, failed_count)
    """
    successful = 0
    failed = 0
    total = len(events)

    print(f"Sending {total} JSON events to webhook (flat format): {webhook_url}", file=sys.stderr)

    # Send each event individually as flat JSON (not wrapped in events array)
    for i, event in enumerate(events):
        event_num = i + 1

        # Send event directly as flat JSON for D&R rule compatibility
        payload = event

        try:
            json_data = json.dumps(payload).encode('utf-8')
            request = Request(
                webhook_url,
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'LogTemplateProcessor/1.0'
                },
                method='POST'
            )

            with urlopen(request, timeout=30) as response:
                status = response.getcode()
                if 200 <= status < 300:
                    successful += 1
                    if event_num % 10 == 0 or event_num == total:
                        print(f"  Progress: {event_num}/{total} events sent", file=sys.stderr)
                else:
                    failed += 1
                    print(f"  Event {event_num}: Failed with HTTP {status}", file=sys.stderr)

        except HTTPError as e:
            failed += 1
            print(f"  Event {event_num}: HTTP error {e.code}: {e.reason}", file=sys.stderr)
        except URLError as e:
            failed += 1
            print(f"  Event {event_num}: URL error: {e.reason}", file=sys.stderr)
        except Exception as e:
            failed += 1
            print(f"  Event {event_num}: Error: {e}", file=sys.stderr)

        # Small delay between requests to avoid overwhelming the webhook
        if delay_between_batches > 0:
            time.sleep(delay_between_batches)

    print(f"Complete: {successful} successful, {failed} failed out of {total} events", file=sys.stderr)
    return successful, failed


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Error: Please provide a template source (file path or URL).", file=sys.stderr)
        sys.exit(1)

    template_source = sys.argv[1]
    output_dest = sys.argv[2] if len(sys.argv) > 2 else None

    # Fetch template from URL or local file
    template_content = fetch_template(template_source)

    # Process the template (returns list for JSON, string for line-based)
    output_content = process_template(template_content)
    is_json_output = isinstance(output_content, list)

    # Write output
    if output_dest:
        if is_url(output_dest):
            # Send to webhook
            if is_json_output:
                # JSON events - send as structured objects
                successful, failed = send_json_events_to_webhook(output_dest, output_content)
            else:
                # Line-based logs - send as raw strings
                log_lines = [line for line in output_content.split('\n') if line.strip()]
                successful, failed = send_to_webhook(output_dest, log_lines)
            if failed > 0:
                sys.exit(1)
        else:
            # Write to local file
            try:
                with open(output_dest, 'w') as f:
                    if is_json_output:
                        json.dump(output_content, f, indent=2)
                    else:
                        f.write(output_content)
                print(f"Successfully wrote output to: {output_dest}", file=sys.stderr)
            except IOError as e:
                print(f"Error writing output file: {e}", file=sys.stderr)
                sys.exit(1)
    else:
        # Print to stdout if no output destination specified
        if is_json_output:
            print(json.dumps(output_content, indent=2))
        else:
            print(output_content)


if __name__ == "__main__":
    main()
