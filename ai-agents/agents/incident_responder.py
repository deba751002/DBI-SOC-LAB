"""
Incident Responder Agent — takes confirmed incidents from Threat Analyst,
creates IRIS cases, coordinates containment, and drives the response lifecycle.
"""
from crewai import Agent, LLM
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from tools import (
    OpenSearchTool,
    IRISCreateCaseTool, IRISAddEvidenceTool, IRISAddTimelineTool,
    VelociraptorHuntTool, VelociraptorVQLTool,
    MISPSearchTool,
)
import os
import json
import uuid
from datetime import datetime


# ── Custom tool: Generate Incident Response Playbook ──────────────────────────
class PlaybookInput(BaseModel):
    incident_title: str = Field(..., description="Short incident name, e.g. 'APT-29 Suspected Intrusion'")
    mitre_technique: str = Field(..., description="Primary MITRE ATT&CK technique ID, e.g. T1486")
    severity: str = Field(default="high", description="critical, high, medium, or low")
    affected_hosts: list[str] = Field(default_factory=list, description="Hostnames involved in the incident")
    affected_users: list[str] = Field(default_factory=list, description="User accounts involved")
    iocs: list[str] = Field(default_factory=list, description="Known IOCs to block/hunt for (IPs, hashes, domains)")


class ResponsePlaybookGeneratorTool(BaseTool):
    name: str = "generate_response_playbook"
    description: str = (
        "Generate a structured incident response playbook (Markdown, NIST lifecycle) for a "
        "confirmed incident, mapping each phase to real automation already available in this "
        "lab — StackStorm actions (block_ip, quarantine_host, enrich_ip, velociraptor_hunt, "
        "create_incident) and the DFIR-IRIS case. Returns the playbook text plus a suggested "
        "file path under soar-playbooks/generated/."
    )
    args_schema: type[BaseModel] = PlaybookInput

    # Phase-2 containment action recommended per technique, drawn from the real
    # StackStorm actions in config/stackstorm/packs/soc/actions/.
    _CONTAINMENT_BY_TECHNIQUE = {
        "T1486": "st2 run soc.quarantine_host host=<host> — ransomware spreads fast, isolate before eradication",
        "T1078": "st2 run soc.quarantine_host host=<host>; force password reset for affected account",
        "T1110": "st2 run soc.block_ip ip=<src_ip>; lock out targeted accounts",
        "T1557.001": "st2 run soc.block_ip ip=<src_ip>; disable LLMNR/NBT-NS via GPO",
        "T1003.001": "st2 run soc.quarantine_host host=<host>; rotate all credentials cached on that host",
        "T1071.004": "st2 run soc.block_ip ip=<src_ip>; block C2 domain at DNS/firewall layer",
        "T1041": "st2 run soc.block_ip ip=<dst_ip>; st2 run soc.quarantine_host host=<host>",
    }

    def _run(self, incident_title: str, mitre_technique: str, severity: str,
             affected_hosts: list, affected_users: list, iocs: list) -> str:
        playbook_id = str(uuid.uuid4())[:8]
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        hosts = ", ".join(affected_hosts) if affected_hosts else "TBD — pending scope confirmation"
        users = ", ".join(affected_users) if affected_users else "TBD — pending scope confirmation"
        ioc_list = "\n".join(f"- `{i}`" for i in iocs) if iocs else "- None identified yet"
        containment = self._CONTAINMENT_BY_TECHNIQUE.get(
            mitre_technique,
            "st2 run soc.quarantine_host host=<host> — no technique-specific playbook yet, default to host isolation",
        )

        playbook = f"""# Incident Response Playbook — {incident_title}

**Playbook ID:** {playbook_id} · **Generated:** {date_str} · **Severity:** {severity.upper()}
**Primary Technique:** {mitre_technique} · **Hosts:** {hosts} · **Users:** {users}

## Known IOCs
{ioc_list}

## Phase 1 — Detection & Analysis
1. `st2 run soc.enrich_ip ip=<src_ip>` — pull threat score, tags, known malware family from MISP/AbuseIPDB.
2. Open DFIR-IRIS and confirm the case created by `soc.create_incident` has correct severity/assets.
3. Cross-reference `{mitre_technique}` in the ATT&CK matrix for related sub-techniques to check.

## Phase 2 — Containment
{containment}

## Phase 3 — Eradication
1. `st2 run soc.velociraptor_hunt host=<host> artifact=process_list` — confirm no persistence mechanism remains.
2. Remove/quarantine the malicious artifact identified during containment.
3. Patch or reconfigure the exploited control (see Detection Engineer's coverage-gap report if this
   technique had no prior detection rule).

## Phase 4 — Recovery
1. Restore host from clean backup or re-image if eradication confidence is low.
2. Re-enable network access via `soc.quarantine_host` reverse action once IRIS case is marked contained.
3. Monitor OpenSearch (`soc-logs-*`, filter `mitre_technique:{mitre_technique}`) for 72h for recurrence.

## Phase 5 — Lessons Learned
1. Update the DFIR-IRIS case with root cause and timeline.
2. If no Sigma/ElastAlert2 rule existed for `{mitre_technique}`, ask the Detection Engineer agent to
   generate one via `generate_sigma_rule`.
3. Add confirmed IOCs to MISP for future correlation.
"""
        return json.dumps({
            "playbook_markdown": playbook,
            "playbook_id": playbook_id,
            "file_suggestion": f"soar-playbooks/generated/{playbook_id}_{incident_title.lower().replace(' ', '_')}.md",
        }, indent=2)


def create_incident_responder() -> Agent:
    # CrewAI 0.105.0 dispatches every LLM call through litellm, which
    # requires a "<provider>/<model>" string (e.g. "ollama/llama3.2:3b") -
    # a langchain_community.llms.Ollama object doesn't supply that prefix
    # and fails with "LLM Provider NOT provided". crewai.LLM is the
    # supported wrapper for this version and speaks litellm's own format.
    llm = LLM(
        model=f"ollama/{os.getenv('OLLAMA_MODEL', 'llama3.2:3b')}",
        base_url=os.getenv("OLLAMA_URL", "http://ollama:11434"),
        temperature=0.1,
    )

    return Agent(
        role="Incident Response Lead (DFIR)",
        goal=(
            "Drive incidents to resolution with speed and thoroughness. "
            "Create structured IRIS cases for every confirmed incident. "
            "Launch Velociraptor forensic hunts to collect evidence. "
            "Build precise attack timelines. Recommend containment and eradication steps. "
            "Ensure nothing falls through the cracks."
        ),
        backstory=(
            "You are a DFIR specialist who has responded to hundreds of breaches — "
            "ransomware, nation-state intrusions, insider threats. You follow the NIST "
            "incident response lifecycle: Preparation, Detection, Containment, Eradication, "
            "Recovery, Lessons Learned. You know that speed and evidence preservation are both "
            "critical — containment before the attacker pivots, but always preserve forensic state. "
            "You use Velociraptor to collect live forensics without disrupting systems. "
            "You document everything in DFIR-IRIS so the team has full visibility. "
            "For every confirmed incident you generate a written response playbook mapping each "
            "NIST lifecycle phase to a concrete StackStorm action so containment isn't improvised."
        ),
        tools=[
            OpenSearchTool(),
            IRISCreateCaseTool(),
            IRISAddEvidenceTool(),
            IRISAddTimelineTool(),
            VelociraptorHuntTool(),
            VelociraptorVQLTool(),
            MISPSearchTool(),
            ResponsePlaybookGeneratorTool(),
        ],
        llm=llm,
        verbose=True,
        allow_delegation=True,
        max_iter=10,
        memory=True,
    )
