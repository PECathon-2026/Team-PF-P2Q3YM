"""Value-free record of one egress decision."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json


@dataclass(frozen=True)
class Receipt:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    blocked: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    rules_fired: tuple[str, ...] = ()
    bytes_sent: int = 0
    image_dropped: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
