#!/usr/bin/env python3
"""StackStorm action: post a critical alert to Slack/Teams via webhook."""
import os
import requests
from st2common.runners.base_action import Action

SEVERITY_EMOJI = {
    "low": ":large_blue_circle:",
    "medium": ":large_yellow_circle:",
    "high": ":large_orange_circle:",
    "critical": ":red_circle:",
}


class NotifySlackAction(Action):
    def run(self, title, message, severity="medium", case_url=""):
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            return (False, {"error": "SLACK_WEBHOOK_URL not configured"})

        emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
        text = f"{emoji} *[{severity.upper()}] {title}*\n{message}"
        if case_url:
            text += f"\n<{case_url}|View case in DFIR-IRIS>"

        # Slack and Teams incoming webhooks both accept this basic shape;
        # Teams needs "text" too (it ignores the unknown "username" field).
        payload = {"text": text, "username": "DBI SOC"}

        try:
            r = requests.post(webhook_url, json=payload, timeout=10)
            r.raise_for_status()
            return (True, {"sent": True})
        except Exception as e:
            return (False, {"error": str(e)})
