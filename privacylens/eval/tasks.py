"""Task metadata and goal predicates for the local synthetic site."""
TASKS = {
    "checkout": {"page": "checkout.html", "goal": "Fill checkout fields from vault refs and stop at Pay for approval."},
    "login": {"page": "login.html", "goal": "Log in with vault credentials; request the one-time code from the user."},
    "support": {"page": "support.html", "goal": "Escalate the open support ticket."},
    "meet": {"page": "meet.html", "goal": "Mute the microphone and open participants."},
    "devsettings": {"page": "devsettings.html", "goal": "Open Webhooks and request a new token with approval."},
}
