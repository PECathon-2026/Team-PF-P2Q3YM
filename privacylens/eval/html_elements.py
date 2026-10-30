"""Standard-library HTML-to-Snapshot parser shared by tests and evaluations."""
from html.parser import HTMLParser
from pathlib import Path

from ..contracts import Element, Snapshot


class _Parser(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__()
        self.nodes = []
        self.stack = []
        self.title = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attributes": dict(attrs), "text": ""}
        self.nodes.append(node)
        if tag == "title":
            self.in_title = True
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        for node in self.stack:
            node["text"] += (" " if node["text"] else "") + data


def parse_html(path) -> Snapshot:
    path = Path(path)
    parser = _Parser()
    parser.feed(path.read_text(encoding="utf-8"))
    elements = tuple(
        Element(tag=node["tag"], text=node["text"], attributes=node["attributes"],
                selector="#" + node["attributes"]["id"] if node["attributes"].get("id") else "")
        for node in parser.nodes
    )
    return Snapshot(url=path.resolve().as_uri(), title=parser.title, elements=elements,
                    metadata={"source_file": path.name})
