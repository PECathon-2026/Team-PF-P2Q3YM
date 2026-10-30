"""Fail-closed egress gate. The transport is always injected by the caller."""
import base64
from dataclasses import is_dataclass, fields
import json
import re

from ..contracts import Element, Finding, GateResult, SanitizedObservation, Snapshot
from ..detect.patterns import scan_text
from .canary import CanaryRegistry, _contains_variant
from .receipt import Receipt

MAX_PAYLOAD_BYTES = 1_048_576
CONTENT_TYPE = "application/json; charset=utf-8"
_PLACEHOLDER = re.compile(r"\[REDACTED:[A-Z_]+(?::[A-Z_]+|#\d+(?:\|(?:network|domain(?:_class)?)=[A-Z]+)?)?\]", re.I)
_IDENTITY_FIELDS = {"id", "selector", "element_id"}


class EgressGateResult(GateResult):
    """Gate result with the requested derived blocked flag, without changing contracts."""
    @property
    def blocked(self):
        return not self.allowed


def _jsonable(value):
    if isinstance(value, Finding):
        return value.to_public()
    if isinstance(value, Snapshot):
        return {"url": value.url, "title": value.title, "elements": [_jsonable(v) for v in value.elements],
                "screenshot": base64.b64encode(value.screenshot).decode("ascii") if value.screenshot is not None else None,
                "timestamp": value.timestamp, "metadata": _jsonable(dict(value.metadata))}
    if isinstance(value, Element):
        return {"tag": value.tag, "text": value.text, "attributes": _jsonable(dict(value.attributes)),
                "selector": value.selector, "bounds": value.bounds, "metadata": _jsonable(dict(value.metadata))}
    if isinstance(value, SanitizedObservation):
        return {"snapshot": _jsonable(value.snapshot), "findings": [_jsonable(v) for v in value.findings],
                "redactions": list(value.redactions), "metadata": _jsonable(dict(value.metadata))}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if is_dataclass(value):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    return value


def _scan_tree(value, counts, path=(), skip_string=False):
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            for finding in scan_text(_PLACEHOLDER.sub("", key_text)):
                counts[finding.kind] = counts.get(finding.kind, 0) + 1
            identity = key_text.lower() in _IDENTITY_FIELDS
            _scan_tree(child, counts, path + (key_text,), skip_string=identity)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_tree(child, counts, path + (str(index),))
    elif isinstance(value, str):
        if skip_string or (path and path[-1].lower() in _IDENTITY_FIELDS):
            return
        scan_value = _PLACEHOLDER.sub("", value)
        if not scan_value:
            return
        for finding in scan_text(scan_value):
            counts[finding.kind] = counts.get(finding.kind, 0) + 1


_MODEL_JSON_KEYS = {"model_json", "model_response_json", "model_output_json", "action_json"}


def _validate_embedded_model_json(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in _MODEL_JSON_KEYS and isinstance(child, str):
                json.loads(child)
            _validate_embedded_model_json(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_embedded_model_json(child)
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        json.loads(value)


def _blocked(reasons, counts=None, rules_fired=(), image_dropped=False, payload_size=0):
    receipt = Receipt(blocked=True, counts=counts or {}, rules_fired=tuple(rules_fired), bytes_sent=0,
                      image_dropped=image_dropped)
    safe_reasons = [{"type": str(r["type"]), "count": int(r["count"]), "rule": str(r["rule"])} for r in reasons]
    return EgressGateResult(allowed=False, reason="egress blocked by privacy checks",
                      metadata={"blocked": True, "reasons": safe_reasons, "receipt": json.loads(receipt.to_json()),
                                "content_type": CONTENT_TYPE, "payload_size": payload_size})


def send(observation, task, history, transport, registry=None, vault=None):
    image_dropped = False
    try:
        try:
            _validate_embedded_model_json(task)
            _validate_embedded_model_json(history)
        except (ValueError, TypeError):
            return _blocked([{"type": "MODEL_JSON", "count": 1, "rule": "malformed_model_json"}],
                            {}, ("malformed_model_json",)), None
        tree = {"observation": _jsonable(observation), "task": _jsonable(task), "history": _jsonable(history)}
        snap = observation.snapshot if isinstance(observation, SanitizedObservation) else None
        if snap is not None and snap.screenshot is not None:
            is_marked_redacted = bool(observation.metadata.get("screenshot_redacted", False))
            if not is_marked_redacted:
                image_dropped = True
                tree["observation"]["snapshot"]["screenshot"] = None
            else:
                try:
                    import pytesseract  # noqa: F401
                except ImportError:
                    image_dropped = True
                    tree["observation"]["snapshot"]["screenshot"] = None
                else:
                    from io import BytesIO
                    from PIL import Image
                    with Image.open(BytesIO(snap.screenshot)) as image:
                        ocr_text = pytesseract.image_to_string(image)
                    image_findings = scan_text(ocr_text)
                    if image_findings:
                        return _blocked([{"type": "IMAGE", "count": len(image_findings), "rule": "ocr_sensitive_text"}],
                                        {f.kind: 1 for f in image_findings}, ("ocr_sensitive_text",), image_dropped)

        # Exact outgoing bytes are canonical JSON encoded as UTF-8.
        payload_bytes = json.dumps(tree, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        reasons = []
        counts = {}
        _scan_tree(tree, counts)
        for kind, count in sorted(counts.items()):
            reasons.append({"type": kind, "count": count, "rule": "scan_text"})
        if registry is not None:
            labels = registry.find(payload_bytes)
            if labels:
                reasons.append({"type": "CANARY", "count": len(labels), "rule": "registered_variant"})
                counts["CANARY"] = len(labels)
        if vault is not None:
            vault_count = 0
            for value in vault.values():
                if _contains_variant(payload_bytes, value):
                    vault_count += 1
            if vault_count:
                reasons.append({"type": "VAULT", "count": vault_count, "rule": "vault_variant"})
                counts["VAULT"] = vault_count
        if CONTENT_TYPE != "application/json; charset=utf-8" or len(payload_bytes) > MAX_PAYLOAD_BYTES:
            reasons.append({"type": "PAYLOAD", "count": 1, "rule": "content_type_or_size"})
        if reasons:
            return _blocked(reasons, counts, tuple(r["rule"] for r in reasons), image_dropped, len(payload_bytes)), None

        response = transport(payload_bytes)
        if not isinstance(response, str):
            return _blocked([{"type": "TRANSPORT", "count": 1, "rule": "unexpected_response_type"}],
                            {}, ("unexpected_response_type",), image_dropped, len(payload_bytes)), None
        receipt = Receipt(blocked=False, counts={}, rules_fired=(), bytes_sent=len(payload_bytes), image_dropped=image_dropped)
        return EgressGateResult(allowed=True, reason="egress checks passed",
                          metadata={"blocked": False, "reasons": [], "receipt": json.loads(receipt.to_json()),
                                    "content_type": CONTENT_TYPE, "payload_size": len(payload_bytes)}), response
    except Exception:
        return _blocked([{"type": "ERROR", "count": 1, "rule": "fail_closed_exception"}],
                        {}, ("fail_closed_exception",), image_dropped), None


def inject_leak(observation, value):
    """Intentional test/demo switch: put a raw value into outgoing metadata."""
    if not isinstance(observation, SanitizedObservation):
        raise TypeError("observation must be SanitizedObservation")
    metadata = dict(observation.metadata)
    metadata["leak_switch"] = value
    return SanitizedObservation(observation.snapshot, observation.findings, observation.redactions, metadata)
