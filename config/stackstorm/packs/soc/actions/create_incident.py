#!/usr/bin/env python3
"""StackStorm action: create DFIR-IRIS incident case."""
import os
import json
import requests
import urllib3
urllib3.disable_warnings()
from st2common.runners.base_action import Action


class CreateIncidentAction(Action):
    def run(self, title, description, severity=3, source_ip="",
            hostname="", mitre_technique="", trigger_ai=True):
        # dfir-iris is the nginx front container - it only ever listens on
        # 443 (TLS), never 8000 (that's iris-app's internal upstream port,
        # not reachable directly from other containers on soc-net).
        iris_url = os.getenv("IRIS_URL", "https://dfir-iris:443")
        iris_key = os.getenv("IRIS_API_KEY", "")
        headers = {"Authorization": f"Bearer {iris_key}", "Content-Type": "application/json"}

        payload = {
            "case_name": title,
            "case_description": (
                f"{description}\n\n"
                f"Source IP: {source_ip or 'N/A'}\n"
                f"Hostname: {hostname or 'N/A'}\n"
                f"MITRE Technique: {mitre_technique or 'N/A'}"
            ),
            "case_customer": 1,
            "case_severity_id": severity,
            "case_classification_id": 1,
            "custom_attributes": {},
        }
        try:
            r = requests.post(f"{iris_url}/api/v1/cases/add",
                              json=payload, headers=headers, verify=False, timeout=15)
            r.raise_for_status()
            case_id = r.json().get("data", {}).get("case_id")

            # Optionally trigger AI agent
            if trigger_ai and case_id:
                try:
                    ai_payload = {
                        "alert_type": mitre_technique or title,
                        "source_ip": source_ip,
                        "hostname": hostname,
                        "severity": ["", "low", "low", "medium", "high", "critical"][severity],
                        "mission": "incident_response",
                    }
                    # crewai-soc's FastAPI app listens on 8500 (see
                    # ai-agents/Dockerfile CREWAI_API_PORT), not 8000 - this
                    # call silently failed against the wrong port for every
                    # incident until now, since the caller swallows the error.
                    crewai_url = os.getenv("CREWAI_URL", "http://crewai-soc:8500")
                    requests.post(f"{crewai_url}/analyze/alert",
                                  json=ai_payload, timeout=5)
                except Exception:
                    pass

            # High/critical cases also ping Slack/Teams - a dashboard only
            # helps if someone is looking at it right now.
            case_url = f"{iris_url}/case?cid={case_id}"
            if severity >= 4:
                webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
                if webhook_url:
                    try:
                        label = ["", "info", "low", "medium", "high", "critical"][severity]
                        requests.post(webhook_url, json={
                            "text": f":red_circle: *[{label.upper()}] {title}*\n{description}\n<{case_url}|View case in DFIR-IRIS>",
                            "username": "DBI SOC",
                        }, timeout=10)
                    except Exception:
                        pass

            return (True, {"case_id": case_id, "url": case_url})
        except Exception as e:
            return (False, {"error": str(e)})
