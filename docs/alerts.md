# Alerts

**Files:** `stage2/alerts.py`, `stage2/static/alerts.html`

Four channels, each independently enabled and configured from the
dashboard's Alerts page: Discord (a webhook), Email (SMTP), Telegram (a
bot), and a generic outgoing webhook for any other platform. All four
go through the same bounded background queue: `dispatch_alert()`
enqueues, a single worker thread drains it, so a slow or hanging SMTP
connection (or an unreachable Telegram API, or a slow custom endpoint)
can never stall the IPC receive hot path. `/api/alerts/test` is the one
exception, it sends synchronously and reports per-channel success or
failure directly, since the entire point of a test button is immediate
feedback on misconfiguration.

## When an alert fires

On a victim's classification changing to or from DDoS, on every new
hard block (Tier 1/2), and on the Tier 4 aggregate rate-limit fallback.
Soft rate-limits (Tier 3) don't alert on their own. A source already
alerted stays suppressed for the configured block duration, so a
sustained attack doesn't spam every enabled channel. A playbook's
`notify` stage (`docs/playbooks.md`) is a second, separately timed
alert on top of this baseline one, not a replacement for it.

## Discord

A webhook URL, created from a Discord server's own integration settings.
Enable, paste the URL, save. The message is sent as the webhook's
`content` field, Markdown-formatted (`**bold**` for the subject line).

## Email (SMTP)

Host, port, a sender address and app password, and one or more
recipients. Uses STARTTLS. Gmail (the default host) needs an app
password, not the account's own login password, generated from the
Google account's security settings once 2-step verification is on.

## Telegram

A bot token and a chat ID. Create the bot through Telegram's own
`@BotFather` (a few messages, no account verification beyond a
Telegram account), add it to the target chat or channel, and use that
chat's ID here. One HTTP POST per alert, to the bot's own
`sendMessage` endpoint.

**Why Telegram has a named integration and WhatsApp does not.**
WhatsApp's official Business Platform needs Meta business
verification, a permanent access token, and operator-side approval of
message templates before it can send anything unprompted at all, none
of which this codebase can set up on an operator's behalf, and the
template requirement in particular means a plain free-form alert
message may not even be deliverable that way. Telegram needs none of
that. Building a WhatsApp integration to the same standard as the other
three channels here would mean shipping something that still can't
send a single message until an operator has separately gone through
Meta's own approval process, a materially different (and heavier)
thing than every other channel on this page. The generic webhook below
is how to reach WhatsApp anyway, through a gateway the operator already
has (a Twilio WhatsApp integration, for example), without this
codebase taking on the official API directly.

## Custom Webhook

A URL and, optionally, a JSON object of extra HTTP headers (for an
`Authorization` or API-key header, whatever the target expects). For
any platform without its own panel above: Slack, Teams, ntfy, PagerDuty-style
receivers, a WhatsApp gateway, or a custom receiver of an operator's
own.

One fixed JSON body is posted on every alert:

```json
{
  "subject": "FLOD System: DDoS detected on 192.0.2.10",
  "message": "...",
  "text": "FLOD System: DDoS detected on 192.0.2.10: ...",
  "title": "FLOD System: DDoS detected on 192.0.2.10"
}
```

`text` is what a Slack- or Microsoft Teams-compatible incoming webhook
expects. `title` alongside `message` is what ntfy expects. `subject`
and `message` separately are there for a custom receiver that wants
them apart rather than pre-joined. There is no per-platform payload
templating, this fixed shape is what every webhook alert sends; a
receiver that needs something else entirely (PagerDuty's Events API,
for instance, wants a `routing_key` and a structured `payload` object,
not this shape) needs a small adapter of the operator's own in front of
it.

## Channel semantics: `all`, or exactly one

Every send path (the baseline alert on a classification change, a
playbook's `notify` stage, `/api/alerts/test`) takes a `channel`:
`"discord"`, `"email"`, `"telegram"`, `"webhook"`, or `"all"` (every
channel that's enabled). `dispatch_alert()`'s default is `"all"`,
matching the system's original, channel-less behaviour before playbooks
existed. An unrecognised channel value falls back to `"all"` rather
than silently dropping the alert, failing safe toward "definitely
delivered" instead of "definitely not."

## What gets redacted

`GET /api/config/alerts` never returns a credential. Each secret field
(`discord_webhook_url`, `smtp_app_password`, `telegram_bot_token`,
`webhook_url`) comes back as a `*_set` boolean instead of its value, and
the dashboard's own "leave blank to keep the current one" pattern is
how each is updated without re-sending it every time. `webhook_headers`
comes back as `webhook_header_names`, the header names only, since a
header value (an API key, a bearer token) is exactly as sensitive as
any other credential here.

An error message logged or returned from a failed send is redacted the
same way before it's shown anywhere: the Discord webhook's path
segment, the Telegram bot token (wherever it appears in the request
URL), the SMTP username and password, and the webhook's own URL and any
configured header value are all matched and stripped, because a network
exception doesn't necessarily contain a credential as one clean,
matchable substring (requests/urllib3 often split a URL's host and path
into separate parts of the message), so each is matched by its own
pattern or literal substring rather than assumed to appear one
particular way.

## Testing

Each channel's "Send Test Alert" button calls `/api/alerts/test`
scoped to that one channel, so testing Telegram doesn't also fire
Discord. `send_discord_alert()`, `send_email_alert()`,
`send_telegram_alert()`, and `send_webhook_alert()` each return
`(success, error_message)`, used identically by the dashboard's test
button and by `_process_alert()` (the live path). `tests/test_alerts.py`
covers channel filtering (`_process_alert()`, `dispatch_alert()`'s
fallback on an unrecognised channel), each new send function's success
and failure paths, and redaction of every credential field from both
`_redact()` and an exception message.
