# DroneWatch

Public threat-alert MVP for region-scoped drone and air-risk awareness.

## Run Locally

```bash
npm install
npm start
```

Open `http://localhost:5173/?quality=low`.

## Notification Delivery

The app stores signups locally and queues alerts or verification requests. To connect a delivery provider, set:

```bash
NOTIFY_WEBHOOK_URL=https://your-provider-webhook.example
PUBLIC_BASE_URL=https://your-deployed-app.example
```

Without `NOTIFY_WEBHOOK_URL`, messages are written to a local outbox for testing.

## Public Reports

Public reports are review-first. A submitted report starts as `needs_review`, can move to `corroborating`, and becomes `corroborated` after the configured number of independent confirmations.

```bash
REPORT_CONFIRMATION_THRESHOLD=2
```

Corroborated public reports are still not official alerts by themselves.
