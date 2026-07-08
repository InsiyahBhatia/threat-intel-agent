"""Shared Pydantic models for the API."""


from pydantic import BaseModel, ConfigDict, Field, field_validator


class InvestigateRequest(BaseModel):
    ioc: str = Field(..., max_length=2048)

    model_config = ConfigDict(
        json_schema_extra={"example": {"ioc": "8.8.8.8"}}
    )


class InvestigateResponse(BaseModel):
    ioc: str
    ioc_type: str
    agent_output: str
    report: dict = Field(default_factory=dict)
    status: str = "success"


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=8192)
    history: list[dict] = Field(default_factory=list, max_length=50)


class BlocklistRequest(BaseModel):
    iocs: list[str] = Field(..., max_length=1000)


class SyslogRequest(BaseModel):
    logs: list[str]


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')


class WorkspaceSwitch(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')


class IgnoreMarkRequest(BaseModel):
    ioc: str
    note: str | None = ""


class BulkInvestigateRequest(BaseModel):
    iocs: list[str] = Field(..., max_length=100)
    background: bool = False


class BulkInvestigateResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[dict]
    errors: list[dict]


_VALID_EVENT_TYPES = {"CRITICAL", "HIGH", "LOW", "CLEAN", "UNKNOWN"}


class WebhookConfig(BaseModel):
    url: str = Field(..., max_length=1024)
    events: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    name: str | None = ""

    @field_validator("events")
    @classmethod
    def validate_events(cls, v):
        for e in v:
            if e not in _VALID_EVENT_TYPES:
                raise ValueError(f"Invalid event type: {e}. Must be one of {_VALID_EVENT_TYPES}")
        return v

    model_config = ConfigDict(
        json_schema_extra={"example": {"url": "https://hooks.example.com/webhook", "events": ["CRITICAL", "HIGH"], "name": "SOC Slack"}}
    )


class ExplainRequest(BaseModel):
    ioc: str


class FeedbackRecord(BaseModel):
    ioc: str = Field(..., max_length=2048)
    features: dict = Field(default_factory=dict)
    predicted_severity: str = Field(..., pattern=r'^(CRITICAL|HIGH|LOW|CLEAN|UNKNOWN)$')
    user_label: str = Field(..., pattern=r'^(CRITICAL|HIGH|LOW|CLEAN|UNKNOWN)$')
    source: str = "user_feedback"


class DBSearchRequest(BaseModel):
    workspace: str = "default"
    severity: str | None = None
    ioc_type: str | None = None
    search: str | None = None
    limit: int = 100
    offset: int = 0


class FeedCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    url: str = Field(..., max_length=2048)
    feed_type: str = "rss"
    interval_minutes: int = 60


class PDFExportRequest(BaseModel):
    ioc: str
    workspace: str = "default"


class YARARequest(BaseModel):
    iocs: list[str] = Field(default_factory=list)
    rule_name: str = "auto_generated_rule"
    description: str = "Auto-generated YARA rule from Threat Intel Agent"


class NotificationChannel(BaseModel):
    enabled: bool = False
    webhook_url: str = ""


class NotificationEmail(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    from_addr: str = ""
    to_addrs: list[str] = Field(default_factory=list)


class NotificationConfig(BaseModel):
    slack: NotificationChannel = Field(default_factory=NotificationChannel)
    teams: NotificationChannel = Field(default_factory=NotificationChannel)
    email: NotificationEmail = Field(default_factory=NotificationEmail)
