"""Generate deterministic scenario pages and value-level ground truth."""
import html
import json
from pathlib import Path

from ..detect.validators import luhn_generate, verhoeff_generate

ROOT = Path(__file__).resolve().parents[2]
PAGES = ("checkout", "login", "support", "meet", "devsettings")


def _item(page, item_id, kind, value):
    return {"id": item_id, "type": kind, "value": value, "selector": f"#{item_id}", "page": f"{page}.html"}


def _field(item, label, name, value, *, field_type="text", autocomplete=None):
    item_id = item["id"]
    auto = f' autocomplete="{html.escape(autocomplete, quote=True)}"' if autocomplete else ""
    return (f'<label for="{html.escape(item_id, quote=True)}">{html.escape(label)}</label>'
            f'<input id="{html.escape(item_id, quote=True)}" name="{html.escape(name, quote=True)}" '
            f'type="{html.escape(field_type, quote=True)}"{auto} value="{html.escape(value, quote=True)}">')


def _decoys(page, invalid_card):
    values = [
        ("ORDER_ID", f"ORD-{page.upper()}-20261030-1042"),
        ("TIMESTAMP", "2026-10-30 14:05:09"),
        ("SKU", "SKU-AB12-CD34"),
        ("VERSION", "Version 1.2.3.4"),
        ("PRICE", "$19.99"),
        ("INVALID_CARD", invalid_card),
    ]
    records, fragments = [], []
    for index, (kind, value) in enumerate(values):
        item_id = f"{page}-decoy-{index}"
        records.append(_item(page, item_id, kind, value))
        fragments.append(f'<p id="{item_id}" class="decoy {kind.lower()}">{html.escape(value)}</p>')
    return records, "".join(fragments)


def generate(output_dir: str | Path = ROOT / "testsite") -> dict:
    """Write the five static HTML evaluation fixtures and their ground truth."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    card = luhn_generate("411111111111", 16)
    aadhaar = verhoeff_generate("23456789012")
    bad_card = card[:-1] + str((int(card[-1]) + 1) % 10)

    sensitive = {}
    body = {}

    # Checkout: each value appears once in the primary form; the card is also
    # represented by four adjacent inputs in an alternate second form.
    page = "checkout"
    values = [
        ("checkout-card-number", "CARD", card, "Card number", "card_number", "text", "cc-number"),
        ("checkout-cvv", "CVV", "321", "Security code", "cvv", "text", "cc-csc"),
        ("checkout-expiry", "EXPIRY", "08/29", "Expiry date", "expiry", "text", "cc-exp"),
        ("checkout-shipping-address", "ADDRESS", "42 Example Road, Pune", "Shipping address", "shipping_address", "text", "street-address"),
        ("checkout-customer-name", "NAME", "Maya Iyer", "Name", "customer_name", "text", "name"),
        ("checkout-customer-phone", "PHONE", "+91 9876543210", "Phone", "customer_phone", "tel", "tel"),
    ]
    items = [_item(page, item_id, kind, value) for item_id, kind, value, *_ in values]
    fields = [_field(item, label, name, value, field_type=field_type, autocomplete=auto)
              for item, (_, _, value, label, name, field_type, auto) in zip(items, values)]
    split = '<form id="checkout-card-split" aria-label="Alternate split card entry"><input id="checkout-card-part-1" name="card_number_part_1" maxlength="4" value="' + card[:4] + '"><input id="checkout-card-part-2" name="card_number_part_2" maxlength="4" value="' + card[4:8] + '"><input id="checkout-card-part-3" name="card_number_part_3" maxlength="4" value="' + card[8:12] + '"><input id="checkout-card-part-4" name="card_number_part_4" maxlength="4" value="' + card[12:] + '"></form>'
    decoy, decoy_html = _decoys(page, bad_card)
    pay = '<button id="checkout-pay" type="submit">Pay</button><script>document.getElementById("checkout-pay").addEventListener("click",()=>document.body.dataset.state="paid")</script>'
    chat = '<textarea id="checkout-chat" name="chat_message" placeholder="Message support"></textarea>'
    sensitive[page] = items; body[page] = '<form id="checkout-primary">' + "".join(fields) + '</form>' + split + pay + chat + decoy_html

    # Login: the password field itself is structurally sensitive; recovery phone is distinct.
    page = "login"
    values = [
        ("login-email", "EMAIL", "user.canary@example.test", "Email", "email", "email", "email"),
        ("login-password", "PASSWORD", "S3cure-Demo-Password-Only", "Password", "password", "password", None),
        ("login-otp", "OTP", "482731", "One-time code", "otp", "text", "one-time-code"),
        ("login-recovery-phone", "PHONE", "+91 9123456780", "Recovery phone", "recovery_phone", "tel", "tel"),
    ]
    items = [_item(page, item_id, kind, value) for item_id, kind, value, *_ in values]
    fields = [_field(item, label, name, value, field_type=field_type, autocomplete=auto)
              for item, (_, _, value, label, name, field_type, auto) in zip(items, values)]
    decoy, decoy_html = _decoys(page, bad_card)
    login_button = '<button id="login-submit" type="button">Log in</button><button id="login-ask-otp" type="button">Ask user for OTP</button><script>document.getElementById("login-submit").onclick=()=>document.body.dataset.state="logged-in"</script>'
    sensitive[page] = items; body[page] = '<form id="login-form">' + "".join(fields) + '</form>' + login_button + decoy_html

    # Support: customer contacts plus one private message containing a name and Aadhaar.
    page = "support"
    values = [
        ("support-customer-phone-1", "PHONE", "+91 9823456701", "Primary customer phone", "customer_phone", "tel", "tel"),
        ("support-customer-phone-2", "PHONE", "+91 9765432108", "Alternate customer phone", "alternate_phone", "tel", "tel"),
        ("support-private-message", "NAME", "Nisha Rao", "Private chat customer name", "message_name", "text", None),
        ("support-private-aadhaar", "AADHAAR", aadhaar, "Aadhaar mentioned in private message", "message_aadhaar", "text", None),
    ]
    # The NAME and Aadhaar seeds are both in one private message. Their separate
    # records point to that same single HTML message location.
    items = [_item(page, item_id, kind, value) for item_id, kind, value, *_ in values]
    fields = [_field(item, label, name, value, field_type=field_type, autocomplete=auto)
              for item, (_, _, value, label, name, field_type, auto) in zip(items[:2], values[:2])]
    message_name, message_aadhaar = values[2][2], values[3][2]
    chat = (f'<article id="support-private-message" aria-label="Private chat message with customer name">'
            f"A customer, {html.escape(message_name)}, writes: My Aadhaar number is {html.escape(message_aadhaar)}."
            " Please keep this private.</article>")
    # Both records refer to the same message element, so each seeded string occurs once.
    items[2]["selector"] = "#support-private-message"
    items[3]["selector"] = "#support-private-message"
    ticket_list = '<section id="support-ticket-list" aria-label="Ticket list"><ul><li>Ticket: delayed parcel</li><li>Ticket: return request</li><li>Ticket: address correction</li></ul></section>'
    decoy, decoy_html = _decoys(page, bad_card)
    support_button = '<button id="support-escalate">Escalate</button><script>document.getElementById("support-escalate").onclick=()=>document.body.dataset.state="escalated"</script>'
    sensitive[page] = items; body[page] = '<section id="support-contacts">' + "".join(fields) + '</section>' + chat + ticket_list + support_button + decoy_html

    # Meeting participants, a face placeholder (no image has been seeded), and chat.
    page = "meet"
    values = [
        ("meet-participant-1-name", "NAME", "Aarav Shah", "Participant one", "participant_name", "text", "name"),
        ("meet-participant-1-email", "EMAIL", "aarav.canary@example.test", "Participant one email", "participant_email", "email", "email"),
        ("meet-participant-2-name", "NAME", "Leena Das", "Participant two", "participant_name_2", "text", "name"),
        ("meet-participant-2-email", "EMAIL", "leena.canary@example.test", "Participant two email", "participant_email_2", "email", "email"),
    ]
    items = [_item(page, item_id, kind, value) for item_id, kind, value, *_ in values]
    fields = [_field(item, label, name, value, field_type=field_type, autocomplete=auto)
              for item, (_, _, value, label, name, field_type, auto) in zip(items, values)]
    face = '<div id="meet-face-placeholder" role="img" aria-label="Face image placeholder">Face image placeholder</div>'
    chat = '<section id="meet-chat-panel" aria-label="Meeting chat"><h2>Meeting chat</h2><p>Welcome to the call. Use the chat for meeting notes.</p></section>'
    decoy, decoy_html = _decoys(page, bad_card)
    controls = '<button id="meet-mute">Mute microphone</button><button id="meet-participants-toggle">Open participants</button><script>document.getElementById("meet-mute").onclick=()=>document.body.dataset.muted="true";document.getElementById("meet-participants-toggle").onclick=()=>document.body.dataset.participants="open"</script>'
    sensitive[page] = items; body[page] = '<form id="meet-participants">' + "".join(fields) + '</form>' + face + chat + controls + decoy_html

    # Developer settings: deliberately fake key/token values, JWT, webhook secret and IPs.
    page = "devsettings"
    values = [
        ("dev-akia-key", "SECRET", "AKIAIOSFODNN7EXAMPLE", "AWS access key", "aws_access_key"),
        ("dev-ghp-key", "SECRET", "ghp_abcdefghijklmnopqrstuvwxyz123456", "GitHub token", "github_token"),
        ("dev-sk-key", "SECRET", "sk-test-abcdefghijklmnopqrstuvwxyz123456", "Service API key", "service_api_key"),
        ("dev-jwt", "SECRET", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.dGVzdHNpZ25hdHVyZQ", "JWT", "jwt_token"),
        ("dev-webhook-secret", "SECRET", "whsec_T8rQ9mP3xV6kL2nB5cD1fH7jK4wZ9sA", "Webhook secret", "webhook_secret"),
        ("dev-ipv4", "IP", "198.51.100.24", "IPv4 address", "server_ipv4"),
        ("dev-ipv6", "IP", "2001:db8::42", "IPv6 address", "server_ipv6"),
    ]
    items = [_item(page, item_id, kind, value) for item_id, kind, value, *_ in values]
    fields = [_field(item, label, name, value)
              for item, (_, _, value, label, name) in zip(items, values)]
    decoy, decoy_html = _decoys(page, bad_card)
    controls = '<button id="dev-webhooks">Webhooks</button><button id="dev-new-token">Generate token</button><script>document.getElementById("dev-webhooks").onclick=()=>document.body.dataset.tab="webhooks";document.getElementById("dev-new-token").onclick=()=>document.body.dataset.state="token-requested"</script>'
    sensitive[page] = items; body[page] = '<form id="developer-settings">' + "".join(fields) + '</form>' + controls + decoy_html

    titles = {"checkout": "Checkout", "login": "Sign in", "support": "Customer support", "meet": "Meeting room", "devsettings": "Developer settings"}
    truth = {"pages": {}, "notes": {"meet.html": ["FACE is not yet seeded; the page contains a labeled image placeholder only."]}}
    for page in PAGES:
        decoy_records, _ = _decoys(page, bad_card)
        filename = f"{page}.html"
        document = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + titles[page] +
                    "</title></head><body><main><h1>" + titles[page] + "</h1>" + body[page] +
                    "</main></body></html>")
        (out / filename).write_text(document, encoding="utf-8")
        truth["pages"][filename] = {"sensitive": sensitive[page], "non_sensitive": decoy_records}
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth


if __name__ == "__main__":
    generate()
