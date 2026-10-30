"""Stable data contracts shared by PrivacyLens modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Finding:
    kind: str = ""
    value: str = field(default="", repr=False)
    confidence: float = 0.0
    source: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_public(self) -> dict[str, Any]:
        """Return log-safe finding metadata without the matched value."""
        return {
            "kind": self.kind,
            "source": self.source,
            "confidence": self.confidence,
            "start": self.metadata.get("start"),
            "end": self.metadata.get("end"),
            "rule": self.metadata.get("rule", self.kind.lower()),
        }


@dataclass(frozen=True)
class Element:
    tag: str = ""
    text: str = ""
    attributes: Mapping[str, str] = field(default_factory=dict)
    selector: str = ""
    bounds: tuple[float, float, float, float] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Snapshot:
    url: str = ""
    title: str = ""
    elements: tuple[Element, ...] = ()
    screenshot: bytes | None = None
    timestamp: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SanitizedObservation:
    snapshot: Snapshot | None = None
    findings: tuple[Finding, ...] = ()
    redactions: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Action:
    kind: str = ""
    target: str = ""
    value: str | None = None
    irreversible: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateResult:
    allowed: bool = False
    requires_confirmation: bool = False
    reason: str = ""
    action: Action | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Vault:
    entries: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Rules:
    allowed_origins: tuple[str, ...] = ("http://localhost", "http://127.0.0.1", "file://")
    entropy_threshold: float = 4.2
    irreversible_keywords: tuple[str, ...] = ("pay", "submit", "delete", "send", "rotate", "confirm")
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RunReport:
    actions: tuple[Action, ...] = ()
    findings: tuple[Finding, ...] = ()
    status: str = ""
    summary: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


# Minimal interfaces keep module boundaries importable while implementations are built.
class Detector:
    def detect(self, observation: SanitizedObservation) -> tuple[Finding, ...]:
        raise NotImplementedError


class Sanitizer:
    def sanitize(self, snapshot: Snapshot) -> SanitizedObservation:
        raise NotImplementedError


class ActionGate:
    def evaluate(self, action: Action, rules: Rules) -> GateResult:
        raise NotImplementedError
