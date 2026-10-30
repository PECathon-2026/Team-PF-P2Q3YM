"""Fail-closed observation sanitization entry point."""
from urllib.parse import urlsplit, urlunsplit
import re

from ..contracts import Finding, SanitizedObservation, Snapshot
from ..detect.patterns import scan_text
from ..detect.structural import scan_elements
from .image import redact_png
from .dom import sanitize_element
from .rules import Rules
from .tokens import SessionTokenizer
from .text import sanitize_text


class SanitizationError(Exception):
    pass


def _safe_href(href):
    parts = urlsplit(href)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))


def _placeholder(kind, raw_value, tokenizer):
    return tokenizer.tokenize(raw_value, kind)


def _redact_string(value, rules, force_kind=None, known_values=(), tokenizer=None):
    if not isinstance(value, str) or not value:
        return value, []
    findings = scan_text(value)
    chosen = [f for f in findings if f.kind in rules.block_types]
    if force_kind in rules.block_types and value.strip():
        replacement = _placeholder(force_kind, value, tokenizer)
        return replacement, findings
    cleaned = sanitize_text(value, chosen, tokenizer)
    for raw, kind in sorted(known_values, key=lambda pair: len(pair[0]), reverse=True):
        if not raw or kind not in rules.block_types:
            continue
        replacement = _placeholder(kind, raw, tokenizer)
        cleaned = re.sub(re.escape(raw), lambda _m, repl=replacement: repl, cleaned, flags=re.I)
    return cleaned, findings


_INTERACTIVE_TAGS = {"a", "button", "input", "select", "textarea", "summary"}
_INTERACTIVE_ROLES = {"button", "link", "textbox", "searchbox", "checkbox", "radio", "switch", "combobox", "listbox", "option", "menuitem", "menuitemcheckbox", "menuitemradio", "slider", "spinbutton", "tab"}


def _minimization_selection(elements, keywords, full_page):
    if full_page:
        return set(range(len(elements)))
    labels_for = {}
    for item in elements:
        attrs = dict(item.attributes or {})
        if item.tag.lower() == "label" and attrs.get("for"):
            labels_for.setdefault(attrs["for"], []).append(item.text)
    tokens = tuple(str(k).casefold() for k in keywords if str(k).strip())
    selected = set()
    for index, element in enumerate(elements):
        attrs = dict(element.attributes or {})
        role = str(attrs.get("role", "")).casefold().split()
        if element.tag.casefold() in _INTERACTIVE_TAGS or any(r in _INTERACTIVE_ROLES for r in role):
            selected.add(index)
            continue
        label_parts = [attrs.get(k, "") for k in ("label", "aria-label", "placeholder", "name", "id", "title")]
        if attrs.get("id"):
            label_parts.extend(labels_for.get(attrs["id"], ()))
        if element.tag.lower() == "label":
            label_parts.append(element.text)
        label = " ".join(str(part) for part in label_parts if part).casefold()
        if tokens and any(token in label for token in tokens):
            selected.add(index)
    return selected


def sanitize(snapshot: Snapshot, vault, rules: Rules, task_keywords=None, full_page=False, tokenizer=None) -> SanitizedObservation:
    try:
        if not isinstance(snapshot, Snapshot):
            raise TypeError("snapshot must be a Snapshot")
        if tokenizer is None:
            tokenizer = vault.session_tokenizer(rules) if vault is not None and hasattr(vault, "session_tokenizer") else SessionTokenizer(rules)
        elements = list(snapshot.elements)
        keywords = task_keywords
        if keywords is None:
            keywords = snapshot.metadata.get("task_keywords", rules.task_keywords)
        if isinstance(keywords, str):
            keywords = (keywords,)
        selection = _minimization_selection(elements, keywords, bool(full_page or not rules.minimize))
        label_map = {}
        for label_element in elements:
            label_attrs = dict(label_element.attributes or {})
            if label_element.tag.lower() == "label" and label_attrs.get("for"):
                label_map.setdefault(label_attrs["for"], []).append(label_element.text)
        structural = scan_elements(elements)
        sensitive_by_id = {}
        for finding in structural:
            if finding.kind in rules.block_types and finding.metadata.get("element_id") is not None:
                sensitive_by_id.setdefault(finding.metadata["element_id"], []).append(finding.kind)
        known_values = []
        for index, element in enumerate(elements):
            attrs = dict(element.attributes or {})
            element_id = attrs.get("id", element.selector or f"element-{index}")
            kinds = sensitive_by_id.get(element_id, [])
            raw_value = attrs.get("value", "")
            if isinstance(raw_value, str) and len(raw_value.strip()) >= 5 and kinds:
                known_values.append((raw_value, kinds[0]))
        output_elements = []
        selected_ids = {
            (dict(elements[i].attributes or {}).get("id") or elements[i].selector or f"element-{i}")
            for i in selection
        }
        all_findings = [f for f in structural if f.metadata.get("element_id") in selected_ids]
        sensitive_boxes = [f.metadata["bbox"] for f in structural if f.kind in rules.block_types and f.metadata.get("bbox")]
        parsed_origin = urlsplit(snapshot.url)
        origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}" if parsed_origin.netloc else f"{parsed_origin.scheme}://"
        for index, element in enumerate(elements):
            if index not in selection:
                continue
            attrs = dict(element.attributes or {})
            element_id = attrs.get("id", element.selector or f"element-{index}")
            kinds = sensitive_by_id.get(element_id, [])
            forced_kind = kinds[0] if kinds else None
            raw_value = str(attrs.get("value", ""))
            if attrs.get("id") in label_map and "label" not in attrs:
                attrs["label"] = " ".join(label_map[attrs["id"]])
                element = type(element)(tag=element.tag, text=element.text, attributes=attrs,
                                        selector=element.selector, bounds=element.bounds, metadata=element.metadata)
            sanitized_element, found = sanitize_element(element, index, forced_kind, rules, known_values, 80, tokenizer)
            all_findings.extend(found)
            sanitized_attrs = dict(sanitized_element.attributes)
            if "href" in attrs and isinstance(attrs["href"], str):
                clean_href, found = _redact_string(_safe_href(attrs["href"]), rules, known_values=known_values, tokenizer=tokenizer)
                sanitized_attrs["href"] = clean_href
                all_findings.extend(found)
            if vault is not None and forced_kind and raw_value.strip() and origin in rules.allowed_origins:
                sanitized_attrs["vault_ref"] = vault.add(raw_value, forced_kind, (origin,))
            output_elements.append(type(element)(tag=sanitized_element.tag, text=sanitized_element.text,
                                                 attributes=sanitized_attrs, selector=element.selector,
                                                 bounds=element.bounds, metadata=sanitized_element.metadata))

        safe_url, url_findings = _redact_string(snapshot.url, rules, known_values=known_values, tokenizer=tokenizer)
        safe_title, title_findings = _redact_string(snapshot.title, rules, known_values=known_values, tokenizer=tokenizer)
        if rules.minimize and not full_page:
            safe_title = safe_title[:80]
        all_findings.extend(url_findings + title_findings)
        screenshot = None
        if snapshot.screenshot is not None:
            screenshot = redact_png(snapshot.screenshot, sensitive_boxes)
        safe_snapshot = Snapshot(
            url=safe_url,
            title=safe_title,
            elements=tuple(output_elements),
            screenshot=screenshot,
            timestamp=snapshot.timestamp,
            metadata={},
        )

        public_findings = []
        seen = set()
        for finding in all_findings:
            identity = (finding.kind, finding.source, finding.metadata.get("element_id"), finding.metadata.get("start"), finding.metadata.get("end"))
            if identity in seen or len(public_findings) >= rules.max_findings_logged:
                continue
            seen.add(identity)
            public = finding.to_public()
            public["rule"] = finding.metadata.get("rule", f"{finding.source}:{finding.kind.lower()}")
            public["explanation"] = f"Redacted because {public['rule']} matched via {finding.source or 'detector'}"
            if finding.metadata.get("element_id") is not None:
                public["element_id"] = finding.metadata["element_id"]
            public_findings.append(public)
        redactions = tuple(f"{finding['kind']}:{finding['rule']}" for finding in public_findings)
        return SanitizedObservation(snapshot=safe_snapshot, findings=tuple(public_findings), redactions=redactions,
                                    metadata={"screenshot_redacted": snapshot.screenshot is None or screenshot is not None,
                                              "minimized": bool(rules.minimize and not full_page)})
    except Exception as exc:
        raise SanitizationError("observation sanitization failed") from exc
