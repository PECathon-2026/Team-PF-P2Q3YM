"""Sanitization policy loaded from JSON, with optional YAML support."""
from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass(frozen=True)
class Rules:
    allowed_origins: tuple[str, ...] = ("http://localhost", "http://127.0.0.1", "file://")
    block_types: tuple[str, ...] = (
        "AADHAAR", "PAN", "CARD", "PHONE", "EMAIL", "OTP", "SECRET", "PASSWORD", "IP", "CVV", "EXPIRY", "ADDRESS", "NAME", "OTHER"
    )
    keep_context: dict[str, str] = field(default_factory=dict)
    max_findings_logged: int = 100
    minimize: bool = True
    task_keywords: tuple[str, ...] = ()


def load_rules(path) -> Rules:
    path = Path(path)
    raw = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".yaml":
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to load YAML rules") from exc
        data = yaml.safe_load(raw) or {}
        if "rules" in data:
            data = {**data, **(data.get("rules") or {})}
    else:
        data = json.loads(raw)
    return Rules(
        allowed_origins=tuple(data.get("allowed_origins", Rules.allowed_origins)),
        block_types=tuple(data.get("block_types", Rules.block_types)),
        keep_context=dict(data.get("keep_context", {})),
        max_findings_logged=int(data.get("max_findings_logged", 100)),
        minimize=bool(data.get("minimize", True)),
        task_keywords=tuple(data.get("task_keywords", ())),
    )
