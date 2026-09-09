from app import notify


def test_send_client_html_email_skips_cleanly_when_unconfigured(monkeypatch):
    """SMTP_HOST is unset in the test environment - this must degrade to
    "didn't send" rather than raise, the same guarantee send_alert_email
    and send_client_email already give (see app/notify.py's module
    docstring)."""
    monkeypatch.setattr(notify, "SMTP_HOST", None)
    sent = notify.send_client_html_email(
        ["client@example.com"],
        "Test subject",
        text_body="plain body",
        html_body="<p>html body</p>",
        logo_bytes=b"not-really-a-png",
        logo_cid="logo",
    )
    assert sent is False


def test_send_client_html_email_skips_with_no_recipients(monkeypatch):
    monkeypatch.setattr(notify, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(notify, "ALERT_FROM", "reports@example.com")
    sent = notify.send_client_html_email([], "Subject", text_body="x", html_body="<p>x</p>")
    assert sent is False


def test_send_client_html_email_filters_blank_recipients(monkeypatch):
    monkeypatch.setattr(notify, "SMTP_HOST", None)
    # Even with an all-blank recipient list, this must not raise before
    # reaching the "not configured" check.
    sent = notify.send_client_html_email(["", None], "Subject", text_body="x", html_body="<p>x</p>")
    assert sent is False
