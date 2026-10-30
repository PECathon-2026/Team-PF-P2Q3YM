"""Provider HTTP transports; all network-capable imports stay in gate/transport."""
import json
import os
import urllib.request


def _post(url, key, payload, timeout, extra_headers=None):
    if not key: raise RuntimeError("provider API key is not configured")
    data = json.dumps(payload).encode("utf-8")
    headers={"Content-Type": "application/json", **(extra_headers or {})}
    if "Authorization" not in headers and "x-api-key" not in headers: headers["Authorization"]="Bearer "+key
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def anthropic_transport(payload, timeout=30):
    key=os.getenv("ANTHROPIC_API_KEY")
    return _post("https://api.anthropic.com/v1/messages", key, payload, timeout,
                 {"x-api-key":key or "", "anthropic-version":"2023-06-01"})


def openai_transport(payload, timeout=30):
    return _post("https://api.openai.com/v1/chat/completions", os.getenv("OPENAI_API_KEY"), payload, timeout)
