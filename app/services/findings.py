from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
IMPORTANT = {"critical", "high", "medium"}


@dataclass
class Finding:
    scanner: str
    severity: str
    title: str
    description: str = ""
    location: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    success: bool
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None
    stats: dict = field(default_factory=dict)

    def important(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in IMPORTANT]

    def sort(self) -> None:
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "error": self.error,
            "notes": self.notes,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    v = value.strip().lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "unknown": "info",
        "negligible": "low",
    }
    return mapping.get(v, "info")
