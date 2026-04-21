"""Email service: send notifications via SMTP/SSL."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Send an email via SMTP SSL. Returns True on success, False on failure."""
    if not settings.SMTP_HOST or not settings.SMTP_USERNAME:
        logger.warning("SMTP not configured — skipping email to %s", to_email)
        return False

    import re
    # Build plain text version by stripping HTML tags
    plain_text = re.sub(r'<[^>]+>', '', html_body)
    plain_text = re.sub(r'\s+', ' ', plain_text).strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.APP_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email

    # Plain text MUST come first, HTML second (RFC 2046 — last part is preferred)
    msg.attach(MIMEText(plain_text, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context) as server:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM_EMAIL, to_email, msg.as_string())
        logger.info("Email sent to %s: %s", to_email, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False


def send_welcome_email(to_email: str, temp_password: str, role: str) -> bool:
    """Send welcome email with temporary password to a newly created user."""
    app_name = settings.APP_NAME
    app_url = settings.APP_URL
    subject = f"Your {app_name} Account Has Been Created"
    html = f"""
    <div style="font-family:sans-serif;max-width:500px;margin:0 auto">
      <h2 style="color:#1e3a5f">Welcome to {app_name}</h2>
      <p>An account has been created for you on the Secure Medical Records platform.</p>
      <table style="margin:1rem 0;font-size:14px">
        <tr><td style="padding:4px 12px 4px 0;color:#666">Email:</td><td><strong>{to_email}</strong></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Role:</td><td><strong>{role}</strong></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Temporary Password:</td><td><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px">{temp_password}</code></td></tr>
      </table>
      <p style="color:#dc2626;font-weight:600">⚠️ You must change your password on first login.</p>
      <p style="margin:1rem 0">
        <a href="{app_url}" target="_blank"
           style="display:inline-block;background:#2563eb;color:#ffffff;padding:10px 24px;
           border-radius:6px;text-decoration:none;font-weight:500">Log In to {app_name}</a>
      </p>
      <p style="color:#666;font-size:12px">If the button doesn't work, copy and paste this link into your browser:<br/>
        <a href="{app_url}" style="color:#2563eb">{app_url}</a></p>
      <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0" />
      <p style="color:#999;font-size:11px">{app_name} — Secure Medical Records Platform<br/>
      If you did not expect this email, please contact your administrator.</p>
    </div>
    """
    return send_email(to_email, subject, html)


def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    """Send password reset token via email."""
    app_name = settings.APP_NAME
    app_url = settings.APP_URL
    subject = f"{app_name} — Password Reset Request"
    html = f"""
    <div style="font-family:sans-serif;max-width:500px;margin:0 auto">
      <h2 style="color:#1e3a5f">Password Reset</h2>
      <p>A password reset was requested for your {app_name} account.</p>
      <p>Your reset token:</p>
      <code style="display:block;background:#f0f0f0;padding:12px;border-radius:4px;font-size:14px;word-break:break-all">{reset_token}</code>
      <p style="margin-top:1rem">
        <a href="{app_url}" style="display:inline-block;background:#2563eb;color:white;padding:10px 24px;
           border-radius:6px;text-decoration:none;font-weight:500">Go to {app_name}</a>
      </p>
      <p style="color:#666;font-size:12px;margin-top:1rem">This token expires in 30 minutes.</p>
      <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0" />
      <p style="color:#999;font-size:11px">{app_name} — Secure Medical Records Platform<br/>
      If you did not request this, ignore this email.</p>
    </div>
    """
    return send_email(to_email, subject, html)
