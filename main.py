#!/usr/bin/env python3
"""
Demo Data Extension - Cloud Run Service

A Flask application that generates sample security events with recent timestamps
and sends them to LimaCharlie webhooks for D&R rule testing.

Endpoints:
    POST /load - Load demo events from template URL to webhook
    GET /health - Health check endpoint
"""

import os
import json
from flask import Flask, request, jsonify

# Import core functions from the existing template processor
from log_template_processor import (
    fetch_template,
    process_template,
    send_json_events_to_webhook,
    send_to_webhook,
    is_url,
)

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Cloud Run."""
    return jsonify({'status': 'healthy'}), 200


@app.route('/load', methods=['POST'])
def load_demo_data():
    """
    Load demo events from a template URL and send to a webhook.

    Request body (JSON):
        template_url: URL to fetch JSON event template from (required)
        webhook_url: Webhook URL to send events to (required)
        delay: Delay between events in seconds (optional, default: 0.05)

    Returns:
        JSON with status, event counts, and any errors
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        template_url = data.get('template_url')
        webhook_url = data.get('webhook_url')
        delay = data.get('delay', 0.05)

        if not template_url:
            return jsonify({'error': 'Missing required parameter: template_url'}), 400

        if not webhook_url:
            return jsonify({'error': 'Missing required parameter: webhook_url'}), 400

        if not is_url(template_url):
            return jsonify({'error': 'template_url must be a valid URL'}), 400

        if not is_url(webhook_url):
            return jsonify({'error': 'webhook_url must be a valid URL'}), 400

        # Fetch and process the template
        template_content = fetch_template(template_url)
        output_content = process_template(template_content)

        # Send to webhook
        if isinstance(output_content, list):
            # JSON events
            successful, failed = send_json_events_to_webhook(
                webhook_url, output_content, delay_between_batches=delay
            )
            total = len(output_content)
        else:
            # Line-based logs
            log_lines = [line for line in output_content.split('\n') if line.strip()]
            successful, failed = send_to_webhook(webhook_url, log_lines)
            total = len(log_lines)

        result = {
            'status': 'success' if failed == 0 else 'partial',
            'template_url': template_url,
            'events_total': total,
            'events_sent': successful,
            'events_failed': failed,
        }

        if failed > 0:
            return jsonify(result), 207  # Multi-Status

        return jsonify(result), 200

    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON in template: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to load demo data: {str(e)}'}), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with usage information."""
    return jsonify({
        'service': 'demo-data-extension',
        'description': 'Generates sample security events for LimaCharlie D&R rule testing',
        'endpoints': {
            'POST /load': {
                'description': 'Load demo events from template URL to webhook',
                'body': {
                    'template_url': 'URL to fetch JSON event template from (required)',
                    'webhook_url': 'Webhook URL to send events to (required)',
                    'delay': 'Delay between events in seconds (optional, default: 0.05)',
                }
            },
            'GET /health': 'Health check endpoint',
        }
    }), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
