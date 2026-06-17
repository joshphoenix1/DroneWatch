# DroneWatch

Public threat-alert app for region-scoped drone, air-raid, and hazard awareness.
Fuses official CAP feeds, vetted OSINT, live hazard data, and community reports.

## Features

- **Live data feeds (no API key):** official CAP/Alert-Hub discovery, USGS earthquakes,
  NASA EONET natural hazards, and regional conflict-news RSS (Al Jazeera / BBC).
- **Real-time push** to open tabs via Server-Sent Events (`/api/stream`), with a 20s poll fallback.
- **Installable PWA** — offline app shell + last-known alerts cached in a service worker.
- **Life-safety tools** — SOS, "I'm safe" family check-in (private circle codes), and a
  nearest shelter / hospital / pharmacy locator (OpenStreetMap Overpass, no key).
- **Accessibility** — screen-reader live-region alerts, reduced-motion support, color cues + labels.
- **Crowd reports** with review-first corroboration; subscriptions + webhook delivery.
- Behind HTTP Basic Auth when `BASIC_AUTH_PASS` is set.

## Run Locally

```bash
npm install
cp .env.example .env   # set BASIC_AUTH_PASS to enable auth (optional)
npm start
```

Open `http://localhost:5173/?quality=low`.

## Deploy (permanent URL)

The repo includes a Render Blueprint and a Dockerfile.

- **Render (free, easiest):** New → Blueprint → connect this repo. It reads `render.yaml`,
  prompts for the `BASIC_AUTH_PASS` secret, and gives a permanent `https://<name>.onrender.com`
  URL (free instances sleep when idle and cold-start on the next request; the URL never changes).
- **Any container host (Fly.io / Railway / Cloud Run / VPS, always-on):**
  ```bash
  docker build -t dronewatch .
  docker run -p 5173:5173 -e BASIC_AUTH_PASS=yourpass dronewatch
  ```

The server honors `PORT` and binds all interfaces, so it works on any platform.

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
