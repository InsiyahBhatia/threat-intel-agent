"""
ThreatReport — Pydantic model for structured output from the agent.
The LLM is prompted to produce output that matches this schema,
which is then validated and serialized to JSON for the API response.
"""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    LOW = "LOW"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"


class MITRETechnique(BaseModel):
    technique_id: str = Field(description="ATT&CK technique ID e.g. T1595.001")
    tactic: str = Field(description="ATT&CK tactic name")
    name: str = Field(description="Full technique name")
    url: str = Field(description="ATT&CK URL for this technique")


class ToolFinding(BaseModel):
    tool_name: str = Field(description="Name of the tool that produced this finding")
    summary: str = Field(description="Key findings from this tool in 1-3 sentences")
    raw_output: str | None = Field(default=None, description="Full raw output from the tool")


class ThreatReport(BaseModel):
    """
    Structured threat intelligence report produced by the agent.
    """
    ioc: str = Field(description="The original IOC that was investigated")
    ioc_type: IOCType = Field(description="Classified type of the IOC")
    severity: SeverityLevel = Field(description="Overall severity rating")
    confidence_score: int = Field(
        ge=0, le=100,
        description="Analyst confidence in the verdict (0-100)"
    )
    summary: str = Field(
        description="2-4 sentence executive summary of the threat findings"
    )
    threat_category: str | None = Field(
        default=None,
        description="Threat category if known (e.g. 'C2 Infrastructure', 'Phishing', 'Botnet')"
    )
    mitre_techniques: list[MITRETechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques observed"
    )
    tool_findings: list[ToolFinding] = Field(
        default_factory=list,
        description="Findings from each tool queried"
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Specific recommended defensive or investigative actions"
    )
    indicators_of_compromise: list[str] = Field(
        default_factory=list,
        description="Additional IOCs discovered during investigation"
    )
    false_positive_notes: str | None = Field(
        default=None,
        description="Any notes about why this might be a false positive"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        description="UTC timestamp of the investigation"
    )

    model_config = ConfigDict(use_enum_values=True)

    def to_markdown(self) -> str:
        """Render the report as a formatted Markdown string."""
        severity_emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠",
            "LOW": "🟢", "CLEAN": "✅", "UNKNOWN": "⬜"
        }
        emoji = severity_emoji.get(self.severity, "⬜")

        lines = [
            "# Threat Intelligence Report",
            "",
            f"**IOC:** `{self.ioc}` ({self.ioc_type})",
            f"**Severity:** {emoji} {self.severity}  |  **Confidence:** {self.confidence_score}/100",
            f"**Timestamp:** {self.timestamp}",
            "",
            "## Summary",
            self.summary,
            "",
        ]

        if self.threat_category:
            lines += [f"**Threat Category:** {self.threat_category}", ""]

        if self.mitre_techniques:
            lines += ["## MITRE ATT&CK Techniques", ""]
            for t in self.mitre_techniques:
                lines.append(f"- [{t.technique_id}]({t.url}) — **{t.tactic}**: {t.name}")
            lines.append("")

        if self.tool_findings:
            lines += ["## Tool Findings", ""]
            for f in self.tool_findings:
                lines += [f"### {f.tool_name}", f.summary, ""]

        if self.recommended_actions:
            lines += ["## Recommended Actions", ""]
            for action in self.recommended_actions:
                lines.append(f"- {action}")
            lines.append("")

        if self.indicators_of_compromise:
            lines += ["## Additional IOCs Discovered", ""]
            for ioc in self.indicators_of_compromise:
                lines.append(f"- `{ioc}`")
            lines.append("")

        if self.false_positive_notes:
            lines += ["## False Positive Notes", self.false_positive_notes, ""]

        return "\n".join(lines)
