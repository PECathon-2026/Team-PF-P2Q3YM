"""Deterministic injected transport for tests and evaluations."""


class MockTransport:
    def __init__(self, response='{"action":"continue"}'):
        self.response = response
        self.captured = []

    def __call__(self, payload_bytes: bytes) -> str:
        self.captured.append(bytes(payload_bytes))
        return self.response
