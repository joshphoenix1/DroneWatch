import http from 'node:http';
import { appendFile, readFile, writeFile, stat, rename } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import dns from 'node:dns';
import net from 'node:net';
import { XMLParser } from 'fast-xml-parser';
import webpush from 'web-push';

// IPv4-only / broken-IPv6 networks make undici's happy-eyeballs hang (ETIMEDOUT)
// on hosts that publish AAAA records (e.g. USGS via CloudFront). Force IPv4 so
// outbound feed fetches stay reliable. Harmless on dual-stack hosts.
dns.setDefaultResultOrder('ipv4first');
net.setDefaultAutoSelectFamily(false);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Minimal .env loader (no dependency). Loads KEY=VALUE lines from a local,
// gitignored .env file so secrets (auth creds, API keys) never live in source.
function loadDotEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!existsSync(envPath)) return;
  try {
    for (const raw of readFileSync(envPath, 'utf8').split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (key && process.env[key] === undefined) process.env[key] = val;
    }
  } catch { /* non-fatal */ }
}
loadDotEnv();

const PORT = Number(process.env.PORT || 5173);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const REPORT_CONFIRMATION_THRESHOLD = Number(process.env.REPORT_CONFIRMATION_THRESHOLD || 2);
// Credentials come from the environment / .env only — never hardcode secrets.
// Auth is enabled only when BASIC_AUTH_PASS is set; otherwise the server is open.
const BASIC_AUTH_USER = process.env.BASIC_AUTH_USER || 'admin';
const BASIC_AUTH_PASS = process.env.BASIC_AUTH_PASS || '';
const BASIC_AUTH_REALM = process.env.BASIC_AUTH_REALM || 'DroneWatch';
const BASIC_AUTH_ENABLED = Boolean(BASIC_AUTH_PASS);

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function checkBasicAuth(req, res) {
  if (!BASIC_AUTH_ENABLED) return true;
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    // Evaluate both comparisons to avoid leaking which field failed via timing.
    const userOk = safeEqual(user, BASIC_AUTH_USER);
    const passOk = safeEqual(pass, BASIC_AUTH_PASS);
    if (userOk && passOk) return true;
  }
  res.writeHead(401, {
    'WWW-Authenticate': `Basic realm="${BASIC_AUTH_REALM}", charset="UTF-8"`,
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Authentication required');
  return false;
}
const REGIONS = [
  {
    id: 'lebanon',
    label: 'Lebanon',
    center: { lat: 33.8938, lon: 35.5018, radiusKm: 220 },
    alertHubCountries: ['lb', 'il', 'jo', 'sy', 'ps', 'cy'],
    note: 'Default Beirut/Lebanon operating picture with nearby regional public CAP sources.'
  },
  {
    id: 'east-med',
    label: 'East Mediterranean',
    center: { lat: 34.6, lon: 35.9, radiusKm: 520 },
    alertHubCountries: ['lb', 'il', 'jo', 'sy', 'ps', 'cy', 'tr', 'eg'],
    note: 'Wider regional watch around Lebanon, Cyprus, Israel, Syria, Jordan, and adjacent sources.'
  },
  {
    id: 'israel-palestine',
    label: 'Israel / Palestinian Territories',
    center: { lat: 31.8, lon: 35.0, radiusKm: 260 },
    alertHubCountries: ['il', 'ps', 'jo', 'cy'],
    note: 'Public CAP availability varies; official local warning apps may be faster than CAP mirrors.'
  },
  {
    id: 'syria',
    label: 'Syria',
    center: { lat: 34.8, lon: 38.9, radiusKm: 520 },
    alertHubCountries: ['sy', 'lb', 'jo', 'tr', 'iq'],
    note: 'Syria-centered source filter with neighboring countries for spillover alerts.'
  },
  {
    id: 'jordan',
    label: 'Jordan',
    center: { lat: 31.2, lon: 36.5, radiusKm: 360 },
    alertHubCountries: ['jo', 'il', 'ps', 'sy', 'sa'],
    note: 'Jordan and adjacent public CAP sources.'
  },
  {
    id: 'cyprus',
    label: 'Cyprus',
    center: { lat: 35.1, lon: 33.3, radiusKm: 260 },
    alertHubCountries: ['cy', 'lb', 'il', 'tr', 'sy'],
    note: 'Cyprus-centered public CAP watch.'
  },
  {
    id: 'ukraine',
    label: 'Ukraine',
    center: { lat: 49.0, lon: 31.3, radiusKm: 760 },
    alertHubCountries: ['ua', 'pl', 'ro', 'md', 'sk', 'hu'],
    note: 'Ukraine-centered public CAP/OSINT watch. Add a vetted air-raid feed for operational use.'
  }
];
const DEFAULT_REGION_ID = process.env.DEFAULT_REGION || 'lebanon';
const CONFIGURED_CAP_FEEDS = splitEnv(process.env.CAP_FEEDS);
const OSINT_JSON_FEEDS = splitEnv(process.env.OSINT_JSON_FEEDS);
const NOTIFY_WEBHOOK_URL = process.env.NOTIFY_WEBHOOK_URL || '';
// Real, no-API-key hazard feeds (USGS earthquakes + NASA EONET). On by default.
const ENABLE_HAZARD_FEEDS = process.env.DISABLE_HAZARD_FEEDS !== '1';
// Web Push (VAPID) — enabled when keys are present in the environment / .env.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const PUSH_ENABLED = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
const PUSH_SUBSCRIBERS_FILE = path.join(__dirname, 'push-subscribers.json');
if (PUSH_ENABLED) {
  try { webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY); }
  catch (e) { console.warn('VAPID setup failed:', e.message); }
}
// Regional conflict-news OSINT (no key). On by default; capped at moderate severity.
const ENABLE_NEWS_FEED = process.env.DISABLE_NEWS_FEED !== '1';
const NEWS_RSS_FEEDS = splitEnv(process.env.NEWS_RSS_FEEDS).length
  ? splitEnv(process.env.NEWS_RSS_FEEDS)
  : [
      'https://www.aljazeera.com/xml/rss/all.xml',
      'https://feeds.bbci.co.uk/news/world/middle_east/rss.xml'
    ];
const REGION_NEWS_TERMS = {
  'lebanon': ['lebanon', 'beirut', 'hezbollah', 'litani', 'bekaa', 'tyre', 'sidon', 'nabatieh', 'baalbek'],
  'east-med': ['lebanon', 'israel', 'syria', 'cyprus', 'mediterranean', 'beirut', 'damascus', 'hezbollah', 'gaza'],
  'israel-palestine': ['israel', 'gaza', 'west bank', 'jerusalem', 'tel aviv', 'idf', 'hamas', 'palestin'],
  'syria': ['syria', 'damascus', 'aleppo', 'homs', 'idlib', 'latakia'],
  'jordan': ['jordan', 'amman', 'aqaba'],
  'cyprus': ['cyprus', 'nicosia', 'larnaca', 'limassol'],
  'ukraine': ['ukraine', 'kyiv', 'kharkiv', 'odesa', 'odessa', 'lviv', 'dnipro', 'russia', 'shahed', 'drone']
};
const SUBSCRIBERS_FILE = path.join(__dirname, 'subscribers.json');
const NOTIFICATION_STATE_FILE = path.join(__dirname, 'notification-state.json');
const NOTIFICATION_OUTBOX_FILE = path.join(__dirname, 'alert-outbox.jsonl');
const MONETIZATION_LEADS_FILE = path.join(__dirname, 'monetization-leads.json');
const PUBLIC_REPORTS_FILE = path.join(__dirname, 'public-reports.json');
const KEYWORDS = (process.env.THREAT_KEYWORDS || [
  'drone', 'uav', 'uas', 'air raid', 'air-raid', 'airstrike', 'air strike',
  'missile', 'rocket', 'hostile aircraft', 'aircraft intrusion', 'shelling',
  'artillery', 'evacuation', 'explosion', 'strike'
].join(','))
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  textNodeName: 'text',
  parseTagValue: false,
  trimValues: true
});

const cacheByRegion = new Map();
const sseClients = new Set(); // live Server-Sent Events subscribers
const notifiedKeys = new Set();
const reportRateLimits = new Map();
const confirmationRateLimits = new Map();

// --- Resource guards: keep memory and disk bounded on long-running servers ---
const NOTIFIED_KEYS_MAX = 5000;                 // cap the in-memory dedupe set
const OUTBOX_MAX_BYTES = 5 * 1024 * 1024;       // rotate alert-outbox.jsonl at 5 MB (keeps 1 backup => ~10 MB max)
const RATE_LIMIT_SWEEP_MS = 10 * 60 * 1000;     // drop idle per-IP rate-limit buckets

// Add a notified key and evict the oldest so the Set never grows unbounded.
function rememberNotified(key) {
  notifiedKeys.add(key);
  while (notifiedKeys.size > NOTIFIED_KEYS_MAX) {
    notifiedKeys.delete(notifiedKeys.values().next().value);
  }
}

// Append to the outbox, rotating the file once it exceeds the size cap.
async function appendOutbox(record) {
  try {
    if (existsSync(NOTIFICATION_OUTBOX_FILE)) {
      const info = await stat(NOTIFICATION_OUTBOX_FILE);
      if (info.size > OUTBOX_MAX_BYTES) {
        await rename(NOTIFICATION_OUTBOX_FILE, `${NOTIFICATION_OUTBOX_FILE}.1`);
      }
    }
  } catch { /* rotation is best-effort */ }
  await appendFile(NOTIFICATION_OUTBOX_FILE, `${JSON.stringify(record)}\n`, 'utf8');
}

// Periodically drop per-IP rate-limit buckets whose timestamps have all aged out.
function sweepRateLimits() {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const map of [reportRateLimits, confirmationRateLimits]) {
    for (const [ip, stamps] of map) {
      if (!stamps.some(ts => ts > cutoff)) map.delete(ip);
    }
  }
}
setInterval(sweepRateLimits, RATE_LIMIT_SWEEP_MS).unref();

function splitEnv(value = '') {
  return value.split(',').map(s => s.trim()).filter(Boolean);
}

function regionFromId(id = DEFAULT_REGION_ID) {
  const normalized = String(id || DEFAULT_REGION_ID).trim().toLowerCase();
  return REGIONS.find(r => r.id === normalized) || REGIONS.find(r => r.id === DEFAULT_REGION_ID) || REGIONS[0];
}

function publicRegions() {
  return REGIONS.map(r => ({
    id: r.id,
    label: r.label,
    center: r.center,
    alertHubCountries: r.alertHubCountries.map(s => s.toUpperCase()),
    note: r.note
  }));
}

function json(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function text(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(payload);
}

async function readBodyJson(req, maxBytes = 20_000) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > maxBytes) throw new Error('Request body too large');
  }
  return body ? JSON.parse(body) : {};
}

async function readJsonFile(filePath, fallback) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

async function writeJsonFile(filePath, payload) {
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

async function fetchText(url, timeoutMs = 8000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      signal: ctl.signal,
      headers: {
        'User-Agent': 'DroneWatchMVP/0.1 public-alert-fusion',
        'Accept': 'application/xml,text/xml,application/rss+xml,application/atom+xml,application/json,text/plain,*/*'
      }
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

async function fetchJson(url, timeoutMs = 8000) {
  const text = await fetchText(url, timeoutMs);
  return JSON.parse(text);
}

// Fetch JSON with one retry on transient failure (network blips, brief 5xx).
async function fetchJsonRetry(url, timeoutMs = 9000, tries = 2) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try { return await fetchJson(url, timeoutMs); }
    catch (e) { lastErr = e; }
  }
  throw lastErr;
}

async function discoverAlertHubFeeds(region) {
  const discovered = [];
  const meta = {
    id: 'alert-hub-source-directory',
    label: 'Alert-Hub CAP source directory',
    type: 'official-directory',
    ok: false,
    checkedAt: new Date().toISOString(),
    detail: ''
  };

  try {
    const doc = await fetchJson('https://alert-hub-sources.s3.amazonaws.com/json');
    for (const row of doc.sources || []) {
      const source = row.source || {};
      if (!region.alertHubCountries.includes(String(source.authorityCountry || '').toLowerCase())) continue;
      if (source.capAlertFeedStatus !== 'operating') continue;
      if (!source.capAlertFeed || source.capAlertFeed === 'none') continue;
      discovered.push({
        url: source.capAlertFeed,
        id: source.sourceId,
        label: source.byLanguage?.[0]?.name || source.sourceId,
        official: Boolean(source.sourceIsOfficial),
        country: source.authorityCountry
      });
    }
    meta.ok = true;
    meta.detail = `${discovered.length} operating feed(s) found for ${region.alertHubCountries.join(', ').toUpperCase()}`;
  } catch (error) {
    meta.detail = error.message;
  }

  return { discovered, meta };
}

function asArray(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function firstText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return firstText(value[0]);
  if (typeof value === 'object') return firstText(value.text ?? value['#text'] ?? value._);
  return '';
}

function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function inferSeverity(textBlob) {
  const text = textBlob.toLowerCase();
  if (/\b(extreme|take shelter|seek shelter|immediate|red alert|air raid|hostile aircraft)\b/.test(text)) return 'extreme';
  if (/\b(severe|warning|evacuation|missile|rocket|drone|uav|airstrike|shelling)\b/.test(text)) return 'severe';
  if (/\b(watch|possible|reported|advisory|caution)\b/.test(text)) return 'moderate';
  return 'minor';
}

function inferType(textBlob) {
  const text = textBlob.toLowerCase();
  if (/\b(drone|uav|uas|hostile aircraft|aircraft intrusion)\b/.test(text)) return 'drone';
  if (/\b(rocket|missile)\b/.test(text)) return 'rocket-missile';
  if (/\b(airstrike|air strike|strike|explosion)\b/.test(text)) return 'airstrike';
  if (/\b(shelling|artillery)\b/.test(text)) return 'shelling';
  if (/\b(evacuation)\b/.test(text)) return 'evacuation';
  return 'public-alert';
}

function keywordMatch(event) {
  const blob = [
    event.title, event.type, event.description, event.instruction, event.source
  ].filter(Boolean).join(' ').toLowerCase();
  return KEYWORDS.length === 0 || KEYWORDS.some(k => blob.includes(k));
}

function distanceKm(lat1, lon1, lat2, lon2) {
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function inRadius(event, region) {
  if (typeof event.lat !== 'number' || typeof event.lon !== 'number') return true;
  return distanceKm(region.center.lat, region.center.lon, event.lat, event.lon) <= region.center.radiusKm;
}

function parseCapAlert(alert, source) {
  const info = asArray(alert.info)[0] || {};
  const area = asArray(info.area)[0] || {};
  const circle = firstText(area.circle);
  const polygon = firstText(area.polygon);
  let lat = null;
  let lon = null;

  if (circle) {
    const [latS, lonS] = circle.split(/\s+/)[0]?.split(',') || [];
    lat = Number(latS);
    lon = Number(lonS);
  } else if (polygon) {
    const points = polygon.split(/\s+/).map(pair => pair.split(',').map(Number)).filter(pair => pair.length === 2);
    if (points.length) {
      lat = points.reduce((sum, p) => sum + p[0], 0) / points.length;
      lon = points.reduce((sum, p) => sum + p[1], 0) / points.length;
    }
  }

  const headline = firstText(info.headline) || firstText(alert.identifier) || 'Public alert';
  const description = firstText(info.description);
  const instruction = firstText(info.instruction);
  const blob = [headline, description, instruction, firstText(info.event)].join(' ');
  const sent = parseDate(alert.sent);
  const expires = parseDate(info.expires);
  const event = {
    id: firstText(alert.identifier) || `${source.id}-${headline}`,
    title: headline,
    type: inferType(blob),
    severity: String(firstText(info.severity) || inferSeverity(blob)).toLowerCase(),
    certainty: String(firstText(info.certainty) || 'unknown').toLowerCase(),
    confidence: source.official ? 'official' : 'osint',
    status: String(firstText(alert.status) || 'actual').toLowerCase(),
    source: source.label,
    sourceId: source.id,
    sourceType: source.official ? 'official-cap' : 'cap',
    description,
    instruction,
    area: firstText(area.areaDesc),
    lat: Number.isFinite(lat) ? lat : null,
    lon: Number.isFinite(lon) ? lon : null,
    updated: sent,
    effective: parseDate(info.effective) || sent,
    expires,
    url: source.url
  };
  return event;
}

async function parseCapFeed(source, region) {
  const sourceStatus = {
    id: source.id,
    label: source.label,
    type: source.official ? 'official-cap' : 'cap',
    url: source.url,
    ok: false,
    checkedAt: new Date().toISOString(),
    count: 0,
    detail: ''
  };

  try {
    const xml = await fetchText(source.url);
    const doc = parser.parse(xml);
    const events = [];

    if (doc.alert) {
      events.push(parseCapAlert(doc.alert, source));
    }

    const rssItems = asArray(doc.rss?.channel?.item);
    for (const item of rssItems) {
      const directAlert = item.alert || item['cap:alert'];
      if (directAlert) {
        events.push(parseCapAlert(directAlert, source));
        continue;
      }
      const title = firstText(item.title) || 'CAP feed item';
      const description = firstText(item.description);
      const link = firstText(item.link) || firstText(item.guid) || source.url;
      const blob = `${title} ${description}`;
      events.push({
        id: firstText(item.guid) || `${source.id}-${title}`,
        title,
        type: inferType(blob),
        severity: inferSeverity(blob),
        certainty: 'unknown',
        confidence: source.official ? 'official' : 'osint',
        status: 'actual',
        source: source.label,
        sourceId: source.id,
        sourceType: source.official ? 'official-cap' : 'cap',
        description,
        instruction: '',
        area: '',
        lat: null,
        lon: null,
        updated: parseDate(item.pubDate),
        effective: parseDate(item.pubDate),
        expires: null,
        url: link
      });
    }

    const atomEntries = asArray(doc.feed?.entry);
    for (const entry of atomEntries) {
      const title = firstText(entry.title) || 'CAP feed entry';
      const summary = firstText(entry.summary) || firstText(entry.content);
      const linkObj = asArray(entry.link).find(l => l.href) || {};
      const blob = `${title} ${summary}`;
      events.push({
        id: firstText(entry.id) || `${source.id}-${title}`,
        title,
        type: inferType(blob),
        severity: inferSeverity(blob),
        certainty: 'unknown',
        confidence: source.official ? 'official' : 'osint',
        status: 'actual',
        source: source.label,
        sourceId: source.id,
        sourceType: source.official ? 'official-cap' : 'cap',
        description: summary,
        instruction: '',
        area: '',
        lat: null,
        lon: null,
        updated: parseDate(entry.updated || entry.published),
        effective: parseDate(entry.published || entry.updated),
        expires: null,
        url: linkObj.href || source.url
      });
    }

    const filtered = events.filter(keywordMatch).filter(e => inRadius(e, region)).map(e => enrichEvent({ ...e, regionId: region.id }));
    sourceStatus.ok = true;
    sourceStatus.count = filtered.length;
    sourceStatus.detail = `${filtered.length} relevant event(s)`;
    return { events: filtered, sourceStatus };
  } catch (error) {
    sourceStatus.detail = error.message;
    return { events: [], sourceStatus };
  }
}

function normalizeOsintEvent(raw, sourceLabel, sourceType = 'osint-json') {
  const blob = [
    raw.title, raw.type, raw.description, raw.instruction, raw.area
  ].filter(Boolean).join(' ');
  const event = {
    id: raw.id || `${sourceLabel}-${raw.title || Date.now()}`,
    title: raw.title || 'OSINT report',
    type: raw.type || inferType(blob),
    severity: String(raw.severity || inferSeverity(blob)).toLowerCase(),
    certainty: String(raw.certainty || 'observed').toLowerCase(),
    confidence: raw.confidence || 'osint',
    status: String(raw.status || 'actual').toLowerCase(),
    source: raw.source || sourceLabel,
    sourceId: raw.sourceId || sourceLabel.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    sourceType,
    regionId: raw.regionId || raw.region || '',
    description: raw.description || '',
    instruction: raw.instruction || '',
    area: raw.area || '',
    lat: Number.isFinite(Number(raw.lat)) ? Number(raw.lat) : null,
    lon: Number.isFinite(Number(raw.lon)) ? Number(raw.lon) : null,
    heading: Number.isFinite(Number(raw.heading)) ? Number(raw.heading) : null,
    speedKph: Number.isFinite(Number(raw.speedKph)) ? Number(raw.speedKph) : null,
    etaMinutes: Number.isFinite(Number(raw.etaMinutes)) ? Number(raw.etaMinutes) : null,
    updated: parseDate(raw.updated || raw.lastSeen || raw.timestamp) || new Date().toISOString(),
    effective: parseDate(raw.effective || raw.updated || raw.timestamp) || new Date().toISOString(),
    expires: parseDate(raw.expires || raw.expiresAt),
    url: raw.url || ''
  };
  return enrichEvent(event);
}

function enrichEvent(event) {
  const now = Date.now();
  const updated = event.updated ? new Date(event.updated).getTime() : NaN;
  const expires = event.expires ? new Date(event.expires).getTime() : NaN;
  const ageSeconds = Number.isFinite(updated) ? Math.max(0, Math.round((now - updated) / 1000)) : null;
  const expired = Number.isFinite(expires) && expires < now;
  return {
    ...event,
    ageSeconds,
    stale: ageSeconds == null ? true : ageSeconds > 15 * 60,
    expired,
    recommendation: event.instruction || defaultRecommendation(event)
  };
}

function defaultRecommendation(event) {
  if (event.severity === 'extreme' || event.type === 'drone' || event.type === 'rocket-missile') {
    return 'Move to shelter or an interior room away from windows. Follow official local instructions.';
  }
  if (event.type === 'evacuation') return 'Follow the evacuation route and official instructions for the named area.';
  return 'Monitor official alerts and avoid exposed areas until the alert is cleared.';
}

function inSelectedRegion(event, region) {
  if (event.regionId && String(event.regionId).toLowerCase() !== region.id) return false;
  return inRadius(event, region);
}

async function readLocalReports(region) {
  const reportPath = path.join(__dirname, 'osint-reports.json');
  const sourceStatus = {
    id: 'local-vetted-osint',
    label: 'Local vetted OSINT reports',
    type: 'local-json',
    ok: false,
    checkedAt: new Date().toISOString(),
    count: 0,
    detail: ''
  };
  try {
    if (!existsSync(reportPath)) {
      sourceStatus.detail = 'osint-reports.json not present';
      return { events: [], sourceStatus };
    }
    const doc = JSON.parse(await readFile(reportPath, 'utf8'));
    const events = asArray(doc.events)
      .map(e => normalizeOsintEvent(e, 'Local vetted OSINT reports', 'local-json'))
      .filter(keywordMatch)
      .filter(e => inSelectedRegion(e, region))
      .map(e => ({ ...e, regionId: region.id }));
    sourceStatus.ok = true;
    sourceStatus.count = events.length;
    sourceStatus.detail = `${events.length} relevant local report(s)`;
    return { events, sourceStatus };
  } catch (error) {
    sourceStatus.detail = error.message;
    return { events: [], sourceStatus };
  }
}

async function fetchOsintJsonFeeds(region) {
  const output = [];
  for (const url of OSINT_JSON_FEEDS) {
    const sourceStatus = {
      id: `osint-${new URL(url).hostname}`,
      label: `OSINT JSON ${new URL(url).hostname}`,
      type: 'osint-json',
      url,
      ok: false,
      checkedAt: new Date().toISOString(),
      count: 0,
      detail: ''
    };
    try {
      const doc = await fetchJson(url);
      const rows = asArray(doc.events || doc.alerts || doc);
      const events = rows
        .map(e => normalizeOsintEvent(e, sourceStatus.label, 'osint-json'))
        .filter(keywordMatch)
        .filter(e => inSelectedRegion(e, region))
        .map(e => ({ ...e, regionId: region.id }));
      sourceStatus.ok = true;
      sourceStatus.count = events.length;
      sourceStatus.detail = `${events.length} relevant event(s)`;
      output.push({ events, sourceStatus });
    } catch (error) {
      sourceStatus.detail = error.message;
      output.push({ events: [], sourceStatus });
    }
  }
  return output;
}

function cleanString(value, max = 200) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

// --- Real no-key hazard feeds -------------------------------------------------
function quakeSeverity(mag) {
  if (mag >= 6) return 'extreme';
  if (mag >= 5) return 'severe';
  if (mag >= 4) return 'moderate';
  return 'minor';
}

// USGS earthquakes (past 24h), GeoJSON, no key. Filtered to the region radius.
async function fetchUsgsQuakes(region) {
  const url = 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson';
  const sourceStatus = {
    id: 'usgs-quakes', label: 'USGS earthquakes (M2.5+, 24h)', type: 'hazard-usgs', url,
    ok: false, checkedAt: new Date().toISOString(), count: 0, detail: ''
  };
  if (!ENABLE_HAZARD_FEEDS) { sourceStatus.detail = 'disabled'; return { events: [], sourceStatus }; }
  try {
    const doc = await fetchJsonRetry(url, 9000);
    const events = [];
    for (const f of asArray(doc.features)) {
      const p = f.properties || {};
      const coords = (f.geometry && Array.isArray(f.geometry.coordinates)) ? f.geometry.coordinates : [];
      const lon = Number(coords[0]);
      const lat = Number(coords[1]);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
      const mag = Number(p.mag);
      const raw = {
        id: f.id || `usgs-${p.code || p.time}`,
        title: p.title || `M ${Number.isFinite(mag) ? mag.toFixed(1) : '?'} earthquake`,
        type: 'earthquake',
        severity: quakeSeverity(mag),
        certainty: 'observed',
        confidence: 'official',
        source: 'USGS',
        sourceId: 'usgs-quakes',
        lat, lon,
        description: `Magnitude ${Number.isFinite(mag) ? mag.toFixed(1) : '?'} earthquake. ${p.place || ''}`.trim(),
        instruction: 'If shaking is felt: Drop, Cover, and Hold On. Stay away from windows and heavy objects. Expect aftershocks.',
        updated: p.time ? new Date(p.time).toISOString() : new Date().toISOString(),
        expires: null,
        url: p.url || url
      };
      const ev = normalizeOsintEvent(raw, sourceStatus.label, 'hazard-usgs');
      if (inRadius(ev, region)) events.push({ ...ev, regionId: region.id });
    }
    sourceStatus.ok = true;
    sourceStatus.count = events.length;
    sourceStatus.detail = `${events.length} quake(s) within ${region.center.radiusKm} km`;
    return { events, sourceStatus };
  } catch (error) {
    sourceStatus.detail = error.message;
    return { events: [], sourceStatus };
  }
}

function eonetMap(categoryId) {
  const m = {
    wildfires: { type: 'wildfire', severity: 'severe' },
    severeStorms: { type: 'storm', severity: 'severe' },
    volcanoes: { type: 'volcano', severity: 'severe' },
    floods: { type: 'flood', severity: 'severe' },
    landslides: { type: 'landslide', severity: 'moderate' },
    dustHaze: { type: 'dust-haze', severity: 'moderate' },
    drought: { type: 'drought', severity: 'minor' }
  };
  return m[categoryId] || { type: 'natural-hazard', severity: 'moderate' };
}

// NASA EONET open natural-hazard events, no key. Filtered to the region radius.
async function fetchEonet(region) {
  const url = 'https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=200';
  const sourceStatus = {
    id: 'nasa-eonet', label: 'NASA EONET natural hazards', type: 'hazard-eonet', url,
    ok: false, checkedAt: new Date().toISOString(), count: 0, detail: ''
  };
  if (!ENABLE_HAZARD_FEEDS) { sourceStatus.detail = 'disabled'; return { events: [], sourceStatus }; }
  try {
    const doc = await fetchJsonRetry(url, 9000);
    const events = [];
    for (const ev of asArray(doc.events)) {
      const cat = asArray(ev.categories)[0] || {};
      const mapped = eonetMap(cat.id);
      const geos = asArray(ev.geometry || ev.geometries);
      const last = geos[geos.length - 1] || {};
      let lon, lat;
      if (last.type === 'Point' && Array.isArray(last.coordinates)) {
        lon = Number(last.coordinates[0]); lat = Number(last.coordinates[1]);
      } else if (Array.isArray(last.coordinates)) {
        const ring = Array.isArray(last.coordinates[0]) ? last.coordinates[0] : [];
        if (ring.length) {
          lon = ring.reduce((s, p) => s + Number(p[0]), 0) / ring.length;
          lat = ring.reduce((s, p) => s + Number(p[1]), 0) / ring.length;
        }
      }
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
      const raw = {
        id: ev.id || `eonet-${ev.title}`,
        title: ev.title || cat.title || 'Natural hazard',
        type: mapped.type,
        severity: mapped.severity,
        certainty: 'observed',
        confidence: 'osint',
        source: 'NASA EONET',
        sourceId: 'nasa-eonet',
        lat, lon,
        description: `${cat.title || 'Natural hazard'}: ${ev.title || ''}`.trim(),
        instruction: 'Monitor official guidance for this hazard and avoid the affected area.',
        updated: last.date ? new Date(last.date).toISOString() : new Date().toISOString(),
        expires: null,
        url: (asArray(ev.sources)[0] || {}).url || 'https://eonet.gsfc.nasa.gov/'
      };
      const e = normalizeOsintEvent(raw, sourceStatus.label, 'hazard-eonet');
      if (inRadius(e, region)) events.push({ ...e, regionId: region.id });
    }
    sourceStatus.ok = true;
    sourceStatus.count = events.length;
    sourceStatus.detail = `${events.length} open hazard(s) within ${region.center.radiusKm} km`;
    return { events, sourceStatus };
  } catch (error) {
    sourceStatus.detail = error.message;
    return { events: [], sourceStatus };
  }
}

function newsSeverity(text) {
  const s = String(text).toLowerCase();
  // Capped at moderate on purpose: unverified news must never trigger severe pages.
  if (/(airstrike|air strike|air raid|missile|drone strike|shelling|explosion|killed|casualt)/.test(s)) return 'moderate';
  return 'minor';
}

// Regional conflict news via public RSS (no key). List-only context (no coords),
// region-filtered by keyword, severity capped at moderate, expires after 6h.
async function fetchNewsFeeds(region) {
  const terms = REGION_NEWS_TERMS[region.id] || [region.label.toLowerCase()];
  const sourceStatus = {
    id: 'osint-news', label: 'Regional conflict news (RSS)', type: 'osint-news',
    ok: false, checkedAt: new Date().toISOString(), count: 0, detail: ''
  };
  if (!ENABLE_NEWS_FEED) { sourceStatus.detail = 'disabled'; return { events: [], sourceStatus }; }
  const events = [];
  let anyOk = false;
  const errors = [];
  for (const url of NEWS_RSS_FEEDS) {
    try {
      const xml = await fetchText(url, 8000);
      const doc = parser.parse(xml);
      for (const item of asArray(doc.rss?.channel?.item)) {
        const title = firstText(item.title);
        const description = cleanString(firstText(item.description), 280);
        const blob = `${title} ${description}`.toLowerCase();
        if (!terms.some(t => blob.includes(t))) continue;
        const pub = parseDate(item.pubDate) || new Date().toISOString();
        events.push(normalizeOsintEvent({
          id: firstText(item.guid) || firstText(item.link) || `news-${title}`,
          title: title || 'Regional news',
          type: 'news',
          severity: newsSeverity(blob),
          certainty: 'reported',
          confidence: 'osint-news',
          source: new URL(url).hostname.replace(/^www\./, ''),
          sourceId: 'osint-news',
          regionId: region.id,
          description,
          instruction: 'Context only — unverified news, not an official alert. Verify before acting.',
          updated: pub,
          expires: new Date(new Date(pub).getTime() + 24 * 60 * 60 * 1000).toISOString(),
          url: firstText(item.link) || url
        }, sourceStatus.label, 'osint-news'));
      }
      anyOk = true;
    } catch (error) {
      errors.push(`${new URL(url).hostname}: ${error.message}`);
    }
  }
  // Dedupe by title and keep the most recent 25.
  const seen = new Set();
  const deduped = events
    .filter(e => { const k = (e.title || '').toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => new Date(b.updated || 0) - new Date(a.updated || 0))
    .slice(0, 25);
  sourceStatus.ok = anyOk;
  sourceStatus.count = deduped.length;
  sourceStatus.detail = anyOk ? `${deduped.length} regional item(s)` : (errors.join('; ') || 'no feeds reachable');
  return { events: deduped, sourceStatus };
}

// --- Life-safety: nearest places (OSM Overpass, no key) ----------------------
const placesCache = new Map(); // `${kind}:${lat2}:${lon2}` -> { until, places }
const PLACES_TTL_MS = 6 * 60 * 60 * 1000;
const PLACES_MAX_CACHE = 200;

function toRad(d) { return d * Math.PI / 180; }
function bearingDeg(lat1, lon1, lat2, lon2) {
  const y = Math.sin(toRad(lon2 - lon1)) * Math.cos(toRad(lat2));
  const x = Math.cos(toRad(lat1)) * Math.sin(toRad(lat2))
    - Math.sin(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.cos(toRad(lon2 - lon1));
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}
function compass(b) { return ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'][Math.round(b / 45) % 8]; }

function overpassQL(kind, lat, lon) {
  const d = 0.09; // ~10 km half-box
  const bb = `(${(lat - d).toFixed(4)},${(lon - d).toFixed(4)},${(lat + d).toFixed(4)},${(lon + d).toFixed(4)})`;
  const sel = {
    shelter: `nwr["amenity"="shelter"]${bb};nwr["emergency"="assembly_point"]${bb};nwr["military"="bunker"]${bb};nwr["building"="bunker"]${bb};`,
    hospital: `nwr["amenity"="hospital"]${bb};nwr["amenity"="clinic"]${bb};`,
    pharmacy: `nwr["amenity"="pharmacy"]${bb};`
  }[kind] || `nwr["amenity"="hospital"]${bb};`;
  return `[out:json][timeout:20];(${sel});out center 80;`;
}

function placeName(kind, tags = {}) {
  if (tags.name) return tags.name;
  if (kind === 'shelter') return tags.shelter_type === 'bomb_shelter' ? 'Bomb shelter' : (tags.emergency === 'assembly_point' ? 'Assembly point' : 'Shelter');
  if (kind === 'hospital') return tags.amenity === 'clinic' ? 'Clinic' : 'Hospital';
  if (kind === 'pharmacy') return 'Pharmacy';
  return 'Place';
}

async function fetchPlaces(kind, lat, lon) {
  kind = ['shelter', 'hospital', 'pharmacy'].includes(kind) ? kind : 'shelter';
  const key = `${kind}:${lat.toFixed(2)}:${lon.toFixed(2)}`;
  const cached = placesCache.get(key);
  if (cached && Date.now() < cached.until) return cached.places;
  const r = await fetch('https://overpass-api.de/api/interpreter', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain', 'User-Agent': 'DroneWatchMVP/0.1 public-alert-fusion' },
    body: overpassQL(kind, lat, lon),
    signal: AbortSignal.timeout(20000)
  });
  if (!r.ok) throw new Error(`overpass HTTP ${r.status}`);
  const doc = await r.json();
  const places = [];
  for (const el of doc.elements || []) {
    const plat = el.lat ?? el.center?.lat;
    const plon = el.lon ?? el.center?.lon;
    if (!Number.isFinite(plat) || !Number.isFinite(plon)) continue;
    const brg = bearingDeg(lat, lon, plat, plon);
    places.push({
      id: `${el.type}/${el.id}`,
      name: placeName(kind, el.tags),
      kind,
      lat: plat, lon: plon,
      distanceKm: Math.round(distanceKm(lat, lon, plat, plon) * 100) / 100,
      bearing: Math.round(brg),
      compass: compass(brg)
    });
  }
  places.sort((a, b) => a.distanceKm - b.distanceKm);
  const top = places.slice(0, 12);
  placesCache.set(key, { until: Date.now() + PLACES_TTL_MS, places: top });
  if (placesCache.size > PLACES_MAX_CACHE) placesCache.delete(placesCache.keys().next().value);
  return top;
}

// --- Life-safety: family "I'm safe" check-in groups ---------------------------
const GROUPS_FILE = path.join(__dirname, 'groups.json');
const GROUP_MAX = 1000;
const GROUP_MEMBER_MAX = 60;
const GROUP_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function randomGroupCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no ambiguous 0/O/1/I/L
  const b = randomBytes(6);
  let s = '';
  for (let i = 0; i < 6; i++) s += alphabet[b[i] % alphabet.length];
  return s;
}
function normalizeCode(code) { return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8); }
function fuzzCoord(n) { return Number.isFinite(Number(n)) ? Math.round(Number(n) * 100) / 100 : null; } // ~1km privacy fuzz

function pruneGroups(doc) {
  const now = Date.now();
  for (const [code, g] of Object.entries(doc.groups)) {
    if (now - new Date(g.createdAt).getTime() > GROUP_TTL_MS) delete doc.groups[code];
  }
  const codes = Object.keys(doc.groups);
  if (codes.length > GROUP_MAX) {
    codes.sort((a, b) => new Date(doc.groups[a].createdAt) - new Date(doc.groups[b].createdAt));
    for (const c of codes.slice(0, codes.length - GROUP_MAX)) delete doc.groups[c];
  }
}
function rosterView(g) {
  return Object.entries(g.members)
    .map(([id, m]) => ({ memberId: id, name: m.name, status: m.status, lat: m.lat, lon: m.lon, updatedAt: m.updatedAt }))
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
}
async function createGroup() {
  const doc = await readJsonFile(GROUPS_FILE, { groups: {} });
  pruneGroups(doc);
  let code;
  do { code = randomGroupCode(); } while (doc.groups[code]);
  doc.groups[code] = { createdAt: new Date().toISOString(), members: {} };
  await writeJsonFile(GROUPS_FILE, doc);
  return code;
}
async function postGroupStatus(code, raw) {
  code = normalizeCode(code);
  const doc = await readJsonFile(GROUPS_FILE, { groups: {} });
  pruneGroups(doc);
  const g = doc.groups[code];
  if (!g) throw badRequest('Unknown group code.');
  const memberId = cleanString(raw.memberId, 40) || randomGroupCode();
  if (!g.members[memberId] && Object.keys(g.members).length >= GROUP_MEMBER_MAX) throw badRequest('Group is full.');
  g.members[memberId] = {
    name: cleanString(raw.name, 40) || 'Member',
    status: ['safe', 'need_help', 'unknown'].includes(raw.status) ? raw.status : 'unknown',
    lat: fuzzCoord(raw.lat),
    lon: fuzzCoord(raw.lon),
    updatedAt: new Date().toISOString()
  };
  await writeJsonFile(GROUPS_FILE, doc);
  return { code, memberId, members: rosterView(g) };
}
async function getGroupRoster(code) {
  code = normalizeCode(code);
  const doc = await readJsonFile(GROUPS_FILE, { groups: {} });
  const g = doc.groups[code];
  return g ? { code, members: rosterView(g) } : null;
}

// --- Web Push (VAPID): wakes a closed device with severe/extreme alerts -------
function subId(endpoint) { return createHash('sha256').update(String(endpoint)).digest('hex').slice(0, 24); }
async function readPushSubs() { return await readJsonFile(PUSH_SUBSCRIBERS_FILE, { subs: [] }); }
async function writePushSubs(doc) { await writeJsonFile(PUSH_SUBSCRIBERS_FILE, doc); }

async function savePushSubscription(raw) {
  if (!PUSH_ENABLED) throw badRequest('Push not configured on this server.');
  const sub = raw && raw.subscription;
  if (!sub || !sub.endpoint) throw badRequest('Missing push subscription.');
  const doc = await readPushSubs();
  const id = subId(sub.endpoint);
  const rec = {
    id, subscription: sub,
    regionId: regionFromId(raw.regionId).id,
    threshold: ['extreme', 'severe', 'moderate'].includes(raw.threshold) ? raw.threshold : 'severe',
    createdAt: new Date().toISOString()
  };
  const existing = doc.subs.find(s => s.id === id);
  if (existing) Object.assign(existing, rec); else doc.subs.push(rec);
  if (doc.subs.length > 5000) doc.subs = doc.subs.slice(-5000);
  await writePushSubs(doc);
  return { id, regionId: rec.regionId, threshold: rec.threshold };
}
async function removePushSubscription(endpoint) {
  const doc = await readPushSubs();
  const id = subId(endpoint || '');
  doc.subs = doc.subs.filter(s => s.id !== id);
  await writePushSubs(doc);
  return { removed: true };
}
async function pushNotifyEvents(events, regionId) {
  if (!PUSH_ENABLED) return;
  const doc = await readPushSubs();
  const subs = doc.subs.filter(s => s.regionId === regionId);
  if (!subs.length) return;
  let changed = false;
  for (const event of events) {
    if (severityRank(event.severity) < 3) continue; // push only severe/extreme by default
    for (const s of subs) {
      if (severityRank(event.severity) < severityRank(s.threshold)) continue;
      const key = `push:${s.id}:${event.id}:${event.updated || event.effective || ''}`;
      if (notifiedKeys.has(key)) continue;
      const payload = JSON.stringify({
        title: `${String(event.severity || 'ALERT').toUpperCase()}: ${event.title || 'Threat alert'}`,
        body: event.recommendation || defaultRecommendation(event),
        severity: event.severity, type: event.type, regionId,
        url: appUrl('/', { region: regionId })
      });
      try {
        await webpush.sendNotification(s.subscription, payload, { TTL: 600, urgency: 'high' });
        rememberNotified(key);
      } catch (err) {
        if (err && (err.statusCode === 404 || err.statusCode === 410)) { s.__dead = true; changed = true; }
      }
    }
  }
  if (changed) { doc.subs = doc.subs.filter(s => !s.__dead); await writePushSubs(doc); }
}
// Background poller so alerts fire even when no browser is open.
async function pushPoll() {
  if (!PUSH_ENABLED) return;
  try {
    const doc = await readPushSubs();
    for (const rid of [...new Set(doc.subs.map(s => s.regionId))]) {
      try { const payload = await threats(rid); await pushNotifyEvents(payload.events || [], rid); } catch { /* skip */ }
    }
  } catch { /* skip */ }
}
setInterval(pushPoll, 60_000).unref();

// --- Live airspace: ADS-B aircraft (free, no key, multi-source fallback) ------
const aircraftCache = new Map(); // regionId -> { until, data }
const AIRCRAFT_TTL_MS = 8000;
const INTEREST_RANK = { emergency: 0, drone: 1, military: 2, unidentified: 3, normal: 4 };

function aircraftInterest(a, uav) {
  const sq = String(a.squawk || '');
  if (['7500', '7600', '7700'].includes(sq) || (a.emergency && a.emergency !== 'none')) return 'emergency';
  if (uav) return 'drone';
  if ((Number(a.dbFlags) & 1) === 1) return 'military';
  if (!String(a.flight || '').trim()) return 'unidentified';
  return 'normal';
}

async function fetchAircraftRaw(lat, lon, nm) {
  const sources = [
    `https://api.adsb.lol/v2/lat/${lat}/lon/${lon}/dist/${nm}`,
    `https://opendata.adsb.fi/api/v2/lat/${lat}/lon/${lon}/dist/${nm}`,
    `https://api.airplanes.live/v2/point/${lat}/${lon}/${nm}`
  ];
  let lastErr;
  for (const url of sources) {
    try {
      const r = await fetch(url, {
        headers: { 'User-Agent': 'DroneWatchMVP/0.1 public-alert-fusion' },
        signal: AbortSignal.timeout(9000)
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const doc = await r.json();
      return { ac: doc.ac || doc.aircraft || [], source: new URL(url).hostname };
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('no aircraft source reachable');
}

async function fetchAircraft(region) {
  const cached = aircraftCache.get(region.id);
  if (cached && Date.now() < cached.until) return cached.data;
  const nm = Math.min(250, Math.max(25, Math.round(region.center.radiusKm / 1.852)));
  const { ac, source } = await fetchAircraftRaw(region.center.lat, region.center.lon, nm);
  const aircraft = [];
  for (const a of ac) {
    const lat = Number(a.lat), lon = Number(a.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    const onGround = a.alt_baro === 'ground';
    const altN = Number.isFinite(Number(a.alt_baro)) ? Number(a.alt_baro) : null;
    const gsN = Number.isFinite(Number(a.gs)) ? Number(a.gs) : null;
    const uav = ['B6', 'B7'].includes(String(a.category || '').toUpperCase()); // ADS-B UAV emitter categories
    const lowSlow = !onGround && altN != null && altN < 2500 && gsN != null && gsN < 90;
    aircraft.push({
      hex: a.hex,
      callsign: String(a.flight || '').trim() || null,
      type: a.t || null,
      lat, lon,
      altFt: onGround ? 0 : (Number.isFinite(Number(a.alt_baro)) ? Number(a.alt_baro) : null),
      onGround,
      groundSpeedKt: Number.isFinite(Number(a.gs)) ? Math.round(Number(a.gs)) : null,
      track: Number.isFinite(Number(a.track)) ? Math.round(Number(a.track)) : null,
      squawk: a.squawk || null,
      category: a.category || null,
      emergency: (a.emergency && a.emergency !== 'none') ? a.emergency : null,
      military: (Number(a.dbFlags) & 1) === 1,
      uav, lowSlow,
      distanceKm: Number.isFinite(Number(a.dst))
        ? Math.round(Number(a.dst) * 1.852 * 10) / 10
        : Math.round(distanceKm(region.center.lat, region.center.lon, lat, lon) * 10) / 10,
      compass: compass(bearingDeg(region.center.lat, region.center.lon, lat, lon)),
      interest: aircraftInterest(a, uav)
    });
  }
  aircraft.sort((x, y) => (INTEREST_RANK[x.interest] - INTEREST_RANK[y.interest]) || x.distanceKm - y.distanceKm);
  const data = {
    ok: true, source, updatedAt: new Date().toISOString(),
    summary: {
      total: aircraft.length,
      military: aircraft.filter(a => a.military).length,
      emergency: aircraft.filter(a => a.emergency).length,
      unidentified: aircraft.filter(a => !a.callsign).length,
      drones: aircraft.filter(a => a.uav).length,
      lowSlow: aircraft.filter(a => a.lowSlow).length
    },
    aircraft: aircraft.slice(0, 80)
  };
  aircraftCache.set(region.id, { until: Date.now() + AIRCRAFT_TTL_MS, data });
  if (aircraftCache.size > 20) aircraftCache.delete(aircraftCache.keys().next().value);
  return data;
}

function requestFingerprint(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || '';
  return createHash('sha256').update(`${ip}|${ua}`).digest('hex').slice(0, 24);
}

function validateContact(channel, contact) {
  if (contact.length < 5 || contact.length > 160) return false;
  if (channel === 'email') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact);
  if (channel === 'sms' || channel === 'whatsapp') return /^[+()\-\d\s.]{7,32}$/.test(contact);
  return false;
}

function badRequest(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

async function readSubscribers() {
  const doc = await readJsonFile(SUBSCRIBERS_FILE, { subscribers: [] });
  return { subscribers: Array.isArray(doc.subscribers) ? doc.subscribers : [] };
}

async function readPublicReportsDoc() {
  const doc = await readJsonFile(PUBLIC_REPORTS_FILE, { reports: [] });
  return { reports: Array.isArray(doc.reports) ? doc.reports : [] };
}

async function writePublicReportsDoc(doc) {
  await writeJsonFile(PUBLIC_REPORTS_FILE, {
    reports: Array.isArray(doc.reports) ? doc.reports : []
  });
}

async function subscribe(raw) {
  const channel = cleanString(raw.channel, 20).toLowerCase();
  const contact = cleanString(raw.contact, 160);
  const threshold = cleanString(raw.threshold || 'severe', 20).toLowerCase();
  const region = regionFromId(raw.regionId || raw.region || DEFAULT_REGION_ID);
  const area = cleanString(raw.area || 'Beirut sector', 100);
  const allowedChannels = new Set(['email', 'sms', 'whatsapp']);
  const allowedThresholds = new Set(['moderate', 'severe', 'extreme']);

  if (!allowedChannels.has(channel)) throw badRequest('Unsupported channel');
  if (!allowedThresholds.has(threshold)) throw badRequest('Unsupported threshold');
  if (!validateContact(channel, contact)) throw badRequest('Invalid contact for selected channel');

  const doc = await readSubscribers();
  const existing = doc.subscribers.find(s => s.channel === channel && s.contact.toLowerCase() === contact.toLowerCase());
  const now = new Date().toISOString();
  if (existing) {
    existing.threshold = threshold;
    existing.regionId = region.id;
    existing.regionLabel = region.label;
    existing.area = area;
    existing.active = true;
    existing.updatedAt = now;
    await writeJsonFile(SUBSCRIBERS_FILE, doc);
    return { id: existing.id, updated: true, verified: Boolean(existing.verified) };
  }

  const sub = {
    id: `sub_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    channel,
    contact,
    threshold,
    regionId: region.id,
    regionLabel: region.label,
    area,
    active: true,
    verified: false,
    createdAt: now,
    updatedAt: now,
    consent: 'Opted in through DroneWatch MVP local signup form'
  };
  doc.subscribers.push(sub);
  await writeJsonFile(SUBSCRIBERS_FILE, doc);
  return { id: sub.id, updated: false, verified: false };
}

async function notificationStatus() {
  const doc = await readSubscribers();
  return {
    subscribers: doc.subscribers.filter(s => s.active).length,
    verifiedSubscribers: doc.subscribers.filter(s => s.active && s.verified).length,
    providerEnabled: Boolean(NOTIFY_WEBHOOK_URL),
    outbox: path.basename(NOTIFICATION_OUTBOX_FILE)
  };
}

async function saveMonetizationLead(raw) {
  const contact = cleanString(raw.contact, 160);
  const tier = cleanString(raw.tier || 'family', 40).toLowerCase();
  const org = cleanString(raw.org || '', 120);
  const allowedTiers = new Set(['family', 'team', 'org', 'sponsor']);

  if (!allowedTiers.has(tier)) throw badRequest('Unsupported plan');
  if (contact.length < 5 || contact.length > 160) throw badRequest('Contact is required');

  const doc = await readJsonFile(MONETIZATION_LEADS_FILE, { leads: [] });
  const leads = Array.isArray(doc.leads) ? doc.leads : [];
  const now = new Date().toISOString();
  const existing = leads.find(l => l.contact.toLowerCase() === contact.toLowerCase() && l.tier === tier);
  if (existing) {
    existing.org = org;
    existing.updatedAt = now;
    existing.status = 'interested';
  } else {
    leads.push({
      id: `lead_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      contact,
      tier,
      org,
      status: 'interested',
      createdAt: now,
      updatedAt: now
    });
  }
  await writeJsonFile(MONETIZATION_LEADS_FILE, { leads });
  return { leads: leads.length };
}

function checkReportRateLimit(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const recent = (reportRateLimits.get(ip) || []).filter(ts => now - ts < windowMs);
  if (recent.length >= 6) throw badRequest('Too many reports from this connection. Try again later.');
  recent.push(now);
  reportRateLimits.set(ip, recent);
}

function checkConfirmationRateLimit(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const recent = (confirmationRateLimits.get(ip) || []).filter(ts => now - ts < windowMs);
  if (recent.length >= 20) throw badRequest('Too many confirmations from this connection. Try again later.');
  recent.push(now);
  confirmationRateLimits.set(ip, recent);
}

function roundedCoordinate(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.round(n * 100) / 100;
}

function confirmationCounts(report) {
  const confirmations = Array.isArray(report.confirmations) ? report.confirmations : [];
  const counts = { confirmed: 0, not_seen: 0, unsure: 0, total: confirmations.length };
  for (const c of confirmations) {
    if (c.response === 'confirmed') counts.confirmed++;
    else if (c.response === 'not_seen') counts.not_seen++;
    else counts.unsure++;
  }
  return counts;
}

function pendingReportStatus(status) {
  return ['needs_review', 'corroborating'].includes(status);
}

function reportKindLabel(kind) {
  return {
    'surveillance-drone': 'surveillance drone',
    'attack-drone': 'suspected attack drone',
    'unknown-drone': 'unknown drone',
    explosion: 'explosion / impact heard',
    other: 'other report'
  }[kind] || 'public report';
}

function publicReportCard(report) {
  const counts = confirmationCounts(report);
  return {
    id: report.id,
    status: report.status || 'needs_review',
    regionId: report.regionId,
    regionLabel: report.regionLabel,
    kind: report.kind,
    kindLabel: reportKindLabel(report.kind),
    area: report.area,
    movement: report.movement,
    count: report.count,
    receivedAt: report.receivedAt,
    observedAt: report.observedAt,
    confirmations: counts,
    confirmationThreshold: REPORT_CONFIRMATION_THRESHOLD,
    handling: 'Unverified public report. Confirm only what you personally saw or heard.'
  };
}

function subscriberMatchesRegion(sub, regionId) {
  if (!sub.regionId) return regionId === DEFAULT_REGION_ID;
  return sub.regionId === regionId;
}

function appUrl(pathname, params = {}) {
  const url = new URL(pathname, PUBLIC_BASE_URL);
  for (const [key, value] of Object.entries(params)) {
    if (value != null && value !== '') url.searchParams.set(key, value);
  }
  return url.toString();
}

async function savePublicReport(raw, req) {
  checkReportRateLimit(req);
  const region = regionFromId(raw.regionId || raw.region || DEFAULT_REGION_ID);
  const kind = cleanString(raw.kind || 'unknown-drone', 40).toLowerCase();
  const area = cleanString(raw.area || '', 120);
  const description = cleanString(raw.description || '', 900);
  const movement = cleanString(raw.movement || 'unknown', 60).toLowerCase();
  const contact = cleanString(raw.contact || '', 160);
  const count = Math.max(1, Math.min(50, Number.parseInt(raw.count || '1', 10) || 1));
  const allowedKinds = new Set(['surveillance-drone', 'attack-drone', 'unknown-drone', 'explosion', 'other']);
  const allowedMovement = new Set(['hovering', 'passing', 'circling', 'approaching', 'leaving', 'unknown']);

  if (!allowedKinds.has(kind)) throw badRequest('Unsupported report type');
  if (!allowedMovement.has(movement)) throw badRequest('Unsupported movement');
  if (area.length < 3) throw badRequest('Area or neighborhood is required');
  if (description.length < 8) throw badRequest('Description is too short');
  if (contact && contact.length < 5) throw badRequest('Optional contact is too short');

  const observedAt = parseDate(raw.observedAt) || new Date().toISOString();
  const observedMs = new Date(observedAt).getTime();
  const now = Date.now();
  if (observedMs < now - 48 * 3600_000 || observedMs > now + 10 * 60_000) {
    throw badRequest('Observation time is outside the accepted window');
  }

  const report = {
    id: `report_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    status: 'needs_review',
    sourceType: 'public-report',
    regionId: region.id,
    regionLabel: region.label,
    kind,
    area,
    description,
    movement,
    count,
    observedAt,
    receivedAt: new Date().toISOString(),
    approximateLat: roundedCoordinate(raw.lat),
    approximateLon: roundedCoordinate(raw.lon),
    reporterContact: contact,
    reporterFingerprint: requestFingerprint(req),
    confirmations: [],
    confirmationThreshold: REPORT_CONFIRMATION_THRESHOLD,
    handling: 'Not alert-grade until reviewed or corroborated. Do not publish reporter contact.'
  };

  const doc = await readPublicReportsDoc();
  doc.reports.push(report);
  await writePublicReportsDoc(doc);
  const confirmationRequests = await queueReportConfirmationRequests(report);
  return {
    id: report.id,
    status: report.status,
    region: report.regionLabel,
    confirmationRequestsQueued: confirmationRequests.queued
  };
}

async function publicReportStatus(regionId) {
  const region = regionFromId(regionId);
  const doc = await readPublicReportsDoc();
  const reports = doc.reports
    .filter(r => !regionId || r.regionId === region.id);
  const pending = reports.filter(r => pendingReportStatus(r.status)).length;
  const corroborated = reports.filter(r => r.status === 'corroborated').length;
  const latest = reports.map(r => r.receivedAt).sort().at(-1) || null;
  const visibleReports = reports
    .filter(r => pendingReportStatus(r.status) || r.status === 'corroborated')
    .sort((a, b) => new Date(b.receivedAt || 0) - new Date(a.receivedAt || 0))
    .slice(0, 12)
    .map(publicReportCard);
  return {
    region: region.id,
    total: reports.length,
    pending,
    corroborated,
    confirmationThreshold: REPORT_CONFIRMATION_THRESHOLD,
    reports: visibleReports,
    latestReceivedAt: latest
  };
}

function reportConfirmationMessage(report) {
  const link = appUrl('/', { quality: 'low', region: report.regionId, confirm: report.id });
  return [
    `VERIFY REQUEST: unverified ${reportKindLabel(report.kind)} reported near ${report.area}, ${report.regionLabel}.`,
    'Confirm only if you personally saw or heard it. Do not go outside to check.',
    `Open DroneWatch: ${link}`
  ].join(' ');
}

async function queueReportConfirmationRequests(report) {
  await loadNotificationState();
  const doc = await readSubscribers();
  const subscribers = doc.subscribers.filter(s =>
    s.active &&
    subscriberMatchesRegion(s, report.regionId) &&
    (!report.reporterContact || s.contact.toLowerCase() !== report.reporterContact.toLowerCase())
  );
  let queued = 0;
  let failed = 0;

  for (const sub of subscribers) {
    const key = `confirm:${sub.id}:${report.id}`;
    if (notifiedKeys.has(key)) continue;
    const payload = {
      id: key,
      kind: 'confirmation-request',
      subscriberId: sub.id,
      channel: sub.channel,
      contact: sub.contact,
      reportId: report.id,
      reportStatus: report.status,
      severity: 'moderate',
      type: report.kind,
      title: `Verify ${reportKindLabel(report.kind)} near ${report.area}`,
      source: 'DroneWatch public report intake',
      confidence: 'unverified-public-report',
      regionId: report.regionId,
      regionLabel: report.regionLabel,
      generatedAt: new Date().toISOString(),
      message: reportConfirmationMessage(report),
      url: appUrl('/', { quality: 'low', region: report.regionId, confirm: report.id })
    };
    try {
      await deliverNotification(payload);
      rememberNotified(key);
      queued++;
    } catch (error) {
      failed++;
      await appendOutbox({ ...payload, delivery: 'failed', error: error.message });
    }
  }

  if (queued) await saveNotificationState();
  return {
    subscribers: subscribers.length,
    providerEnabled: Boolean(NOTIFY_WEBHOOK_URL),
    queued,
    failed
  };
}

async function saveReportConfirmation(raw, req) {
  checkConfirmationRateLimit(req);
  const reportId = cleanString(raw.reportId || raw.id, 90);
  const response = cleanString(raw.response || 'confirmed', 30).toLowerCase();
  const note = cleanString(raw.note || '', 500);
  const contact = cleanString(raw.contact || '', 160);
  const allowedResponses = new Set(['confirmed', 'not_seen', 'unsure']);

  if (!reportId) throw badRequest('Report id is required');
  if (!allowedResponses.has(response)) throw badRequest('Unsupported confirmation response');
  if (contact && contact.length < 5) throw badRequest('Optional contact is too short');

  const doc = await readPublicReportsDoc();
  const report = doc.reports.find(r => r.id === reportId);
  if (!report) throw badRequest('Report not found');
  if (report.status === 'dismissed') throw badRequest('This report is closed');

  const now = new Date().toISOString();
  const fingerprint = requestFingerprint(req);
  if (report.reporterFingerprint && report.reporterFingerprint === fingerprint) {
    throw badRequest('Original reporter cannot confirm the same report');
  }
  const confirmations = Array.isArray(report.confirmations) ? report.confirmations : [];
  const existing = confirmations.find(c => c.fingerprint === fingerprint);
  const entry = {
    id: existing?.id || `conf_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    response,
    note,
    contact,
    fingerprint,
    receivedAt: existing?.receivedAt || now,
    updatedAt: now
  };
  if (existing) Object.assign(existing, entry);
  else confirmations.push(entry);

  report.confirmations = confirmations;
  report.confirmationThreshold = REPORT_CONFIRMATION_THRESHOLD;
  const counts = confirmationCounts(report);
  if (counts.confirmed >= REPORT_CONFIRMATION_THRESHOLD) report.status = 'corroborated';
  else if (counts.confirmed > 0) report.status = 'corroborating';
  else report.status = 'needs_review';
  report.updatedAt = now;

  await writePublicReportsDoc(doc);
  return {
    id: report.id,
    status: report.status,
    confirmations: counts,
    confirmationThreshold: REPORT_CONFIRMATION_THRESHOLD
  };
}

async function loadNotificationState() {
  const doc = await readJsonFile(NOTIFICATION_STATE_FILE, { sent: [] });
  for (const key of doc.sent || []) notifiedKeys.add(key);
}

async function saveNotificationState() {
  await writeJsonFile(NOTIFICATION_STATE_FILE, { sent: [...notifiedKeys].slice(-5000) });
}

function notificationMessage(event) {
  const level = String(event.severity || 'alert').toUpperCase();
  const area = event.area ? ` Area: ${event.area}.` : '';
  const age = event.ageSeconds == null ? '' : ` Updated ${Math.round(event.ageSeconds / 60)}m ago.`;
  return `${level}: ${event.title || 'Threat alert'}.${area} ${event.recommendation || defaultRecommendation(event)}${age}`.replace(/\s+/g, ' ').trim();
}

async function deliverNotification(payload) {
  if (!NOTIFY_WEBHOOK_URL) {
    await appendOutbox({ ...payload, delivery: 'queued-local' });
    return 'queued-local';
  }

  const r = await fetch(NOTIFY_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!r.ok) throw new Error(`notify webhook HTTP ${r.status}`);
  await appendOutbox({ ...payload, delivery: 'webhook-sent' });
  return 'webhook-sent';
}

async function queueNotifications(events) {
  await loadNotificationState();
  const doc = await readSubscribers();
  const subscribers = doc.subscribers.filter(s => s.active);
  let queued = 0;
  let failed = 0;

  for (const event of events) {
    if (event.sourceType === 'demo' && process.env.SEND_DEMO_ALERTS !== '1') continue;
    for (const sub of subscribers) {
      if (severityRank(event.severity) < severityRank(sub.threshold)) continue;
      const key = `${sub.id}:${event.id}:${event.updated || event.effective || ''}`;
      if (notifiedKeys.has(key)) continue;
      const payload = {
        id: key,
        subscriberId: sub.id,
        channel: sub.channel,
        contact: sub.contact,
        threshold: sub.threshold,
        eventId: event.id,
        severity: event.severity,
        type: event.type,
        title: event.title,
        source: event.source,
        confidence: event.confidence,
        regionId: event.regionId || '',
        regionLabel: event.regionLabel || '',
        generatedAt: new Date().toISOString(),
        message: notificationMessage(event),
        url: event.url || ''
      };
      try {
        await deliverNotification(payload);
        rememberNotified(key);
        queued++;
      } catch (error) {
        failed++;
        await appendOutbox({ ...payload, delivery: 'failed', error: error.message });
      }
    }
  }

  if (queued) await saveNotificationState();
  return {
    subscribers: subscribers.length,
    providerEnabled: Boolean(NOTIFY_WEBHOOK_URL),
    queued,
    failed
  };
}

function demoEvents(region) {
  if (process.env.MVP_DEMO !== '1') return [];
  return [{
    id: `demo-drone-inbound-${region.id}`,
    title: `DEMO: Suspected UAV alert near ${region.label}`,
    type: 'drone',
    severity: 'severe',
    certainty: 'possible',
    confidence: 'demo',
    status: 'exercise',
    source: 'MVP demo generator',
    sourceId: 'demo',
    sourceType: 'demo',
    description: 'Synthetic event for UI validation only. Not a real alert.',
    instruction: 'Demo only: verify marker rendering and alert workflow.',
    area: region.label,
    lat: region.center.lat + 0.05,
    lon: region.center.lon + 0.07,
    regionId: region.id,
    regionLabel: region.label,
    heading: 215,
    speedKph: 120,
    etaMinutes: 8,
    updated: new Date().toISOString(),
    effective: new Date().toISOString(),
    expires: new Date(Date.now() + 10 * 60_000).toISOString(),
    url: ''
  }].map(enrichEvent);
}

async function buildThreatPayload(region) {
  const { discovered, meta } = await discoverAlertHubFeeds(region);
  const capFeeds = [
    ...CONFIGURED_CAP_FEEDS.map((url, i) => ({
      url,
      id: `configured-cap-${i + 1}`,
      label: `Configured CAP feed ${i + 1}`,
      official: false,
      country: 'configured'
    })),
    ...discovered
  ];

  const sourceStatuses = [meta];
  const eventSets = [];
  const capResults = await Promise.all(capFeeds.map(source => parseCapFeed(source, region)));
  for (const result of capResults) {
    eventSets.push(result.events);
    sourceStatuses.push(result.sourceStatus);
  }

  const localReports = await readLocalReports(region);
  eventSets.push(localReports.events);
  sourceStatuses.push(localReports.sourceStatus);

  const osintResults = await fetchOsintJsonFeeds(region);
  for (const result of osintResults) {
    eventSets.push(result.events);
    sourceStatuses.push(result.sourceStatus);
  }

  const hazardResults = await Promise.all([fetchUsgsQuakes(region), fetchEonet(region), fetchNewsFeeds(region)]);
  for (const result of hazardResults) {
    eventSets.push(result.events);
    sourceStatuses.push(result.sourceStatus);
  }

  const demo = demoEvents(region);
  if (demo.length) {
    eventSets.push(demo);
    sourceStatuses.push({
      id: 'demo',
      label: 'MVP demo generator',
      type: 'demo',
      ok: true,
      checkedAt: new Date().toISOString(),
      count: demo.length,
      detail: 'Synthetic event enabled by MVP_DEMO=1'
    });
  }

  const seen = new Set();
  const events = eventSets.flat()
    .filter(e => !e.expired)
    .filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    })
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity)
      || new Date(b.updated || 0) - new Date(a.updated || 0));
  const notifications = await queueNotifications(events);
  pushNotifyEvents(events, region.id).catch(() => {}); // fire-and-forget web push
  const reportStatus = await publicReportStatus(region.id);

  return {
    generatedAt: new Date().toISOString(),
    region: {
      id: region.id,
      label: region.label,
      note: region.note
    },
    center: region.center,
    filters: {
      alertHubCountries: region.alertHubCountries.map(s => s.toUpperCase()),
      keywords: KEYWORDS,
      radiusKm: region.center.radiusKm
    },
    summary: {
      activeEvents: events.length,
      criticalEvents: events.filter(e => ['extreme', 'severe'].includes(e.severity)).length,
      sourcesOk: sourceStatuses.filter(s => s.ok).length,
      sourcesTotal: sourceStatuses.length,
      subscribers: notifications.subscribers,
      notificationsQueued: notifications.queued,
      publicReportsPending: reportStatus.pending,
      publicReportsCorroborated: reportStatus.corroborated
    },
    notifications,
    publicReports: reportStatus,
    sources: sourceStatuses,
    events
  };
}

function severityRank(severity) {
  return { extreme: 4, severe: 3, moderate: 2, minor: 1, unknown: 0 }[severity] ?? 0;
}

async function threats(regionId) {
  const region = regionFromId(regionId);
  const cached = cacheByRegion.get(region.id);
  if (cached && Date.now() < cached.until) return cached.payload;
  const payload = await buildThreatPayload(region);
  cacheByRegion.set(region.id, { payload, until: Date.now() + 20_000 });
  return payload;
}

// Push fresh threats to every connected SSE client, computing each region once.
async function broadcastThreats() {
  if (!sseClients.size) return;
  const byRegion = new Map();
  for (const c of sseClients) byRegion.set(c.regionId, null);
  for (const rid of byRegion.keys()) {
    try { byRegion.set(rid, await threats(rid)); } catch { /* skip region */ }
  }
  for (const c of [...sseClients]) {
    const payload = byRegion.get(c.regionId);
    if (!payload) continue;
    try {
      c.res.write(`event: threats\ndata: ${JSON.stringify(payload)}\n\n`);
    } catch {
      sseClients.delete(c);
    }
  }
}
setInterval(broadcastThreats, 20_000).unref();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let requested = decodeURIComponent(url.pathname);
  if (requested === '/') requested = '/index.html';
  const filePath = path.normalize(path.join(__dirname, requested));
  if (!filePath.startsWith(__dirname)) return text(res, 403, 'Forbidden');
  try {
    const body = await readFile(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(body);
  } catch {
    text(res, 404, 'Not found');
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (!checkBasicAuth(req, res)) return;
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === '/api/health') {
      return json(res, 200, { ok: true, generatedAt: new Date().toISOString() });
    }
    if (url.pathname === '/api/regions') {
      return json(res, 200, { ok: true, defaultRegion: DEFAULT_REGION_ID, regions: publicRegions() });
    }
    if (url.pathname === '/api/subscribe' && req.method === 'POST') {
      const result = await subscribe(await readBodyJson(req));
      cacheByRegion.clear();
      return json(res, 200, { ok: true, ...result });
    }
    if (url.pathname === '/api/monetization' && req.method === 'POST') {
      const result = await saveMonetizationLead(await readBodyJson(req));
      return json(res, 200, { ok: true, ...result });
    }
    if (url.pathname === '/api/report' && req.method === 'POST') {
      const result = await savePublicReport(await readBodyJson(req), req);
      cacheByRegion.clear();
      return json(res, 200, { ok: true, ...result });
    }
    if (url.pathname === '/api/report-confirmation' && req.method === 'POST') {
      const result = await saveReportConfirmation(await readBodyJson(req), req);
      cacheByRegion.clear();
      return json(res, 200, { ok: true, ...result });
    }
    if (url.pathname === '/api/report-status') {
      return json(res, 200, { ok: true, ...(await publicReportStatus(url.searchParams.get('region'))) });
    }
    if (url.pathname === '/api/public-reports') {
      return json(res, 200, { ok: true, ...(await publicReportStatus(url.searchParams.get('region'))) });
    }
    if (url.pathname === '/api/notifications') {
      return json(res, 200, { ok: true, ...(await notificationStatus()) });
    }
    if (url.pathname === '/api/threats') {
      return json(res, 200, await threats(url.searchParams.get('region')));
    }
    if (url.pathname === '/api/stream') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
      });
      res.write('retry: 10000\n\n');
      const client = { res, regionId: regionFromId(url.searchParams.get('region')).id };
      sseClients.add(client);
      threats(client.regionId)
        .then(payload => { try { res.write(`event: threats\ndata: ${JSON.stringify(payload)}\n\n`); } catch { /* gone */ } })
        .catch(() => {});
      const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* gone */ } }, 25_000);
      req.on('close', () => { clearInterval(ping); sseClients.delete(client); });
      return;
    }
    if (url.pathname === '/api/places') {
      const lat = Number(url.searchParams.get('lat'));
      const lon = Number(url.searchParams.get('lon'));
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return json(res, 400, { ok: false, error: 'lat and lon are required' });
      const kind = url.searchParams.get('kind') || 'shelter';
      try {
        const places = await fetchPlaces(kind, lat, lon);
        return json(res, 200, {
          ok: true, kind, count: places.length, places,
          disclaimer: 'Locations are from OpenStreetMap and may be incomplete or inaccurate. Follow official civil-defense instructions first.'
        });
      } catch (error) {
        return json(res, 200, { ok: false, error: error.message, places: [] });
      }
    }
    if (url.pathname === '/api/push/key') {
      return json(res, 200, { ok: true, enabled: PUSH_ENABLED, key: VAPID_PUBLIC_KEY });
    }
    if (url.pathname === '/api/push/subscribe' && req.method === 'POST') {
      return json(res, 200, { ok: true, ...(await savePushSubscription(await readBodyJson(req))) });
    }
    if (url.pathname === '/api/push/unsubscribe' && req.method === 'POST') {
      const b = await readBodyJson(req);
      return json(res, 200, { ok: true, ...(await removePushSubscription(b.endpoint || (b.subscription && b.subscription.endpoint))) });
    }
    if (url.pathname === '/api/aircraft') {
      try {
        return json(res, 200, await fetchAircraft(regionFromId(url.searchParams.get('region'))));
      } catch (error) {
        return json(res, 200, { ok: false, error: error.message, aircraft: [], summary: { total: 0 } });
      }
    }
    if (url.pathname === '/api/group' && req.method === 'POST') {
      return json(res, 200, { ok: true, code: await createGroup() });
    }
    {
      const m = url.pathname.match(/^\/api\/group\/([A-Za-z0-9]{4,8})\/(status|roster)$/);
      if (m) {
        if (m[2] === 'status' && req.method === 'POST') {
          checkConfirmationRateLimit(req);
          return json(res, 200, { ok: true, ...(await postGroupStatus(m[1], await readBodyJson(req))) });
        }
        if (m[2] === 'roster') {
          const roster = await getGroupRoster(m[1]);
          if (!roster) return json(res, 404, { ok: false, error: 'Unknown group code' });
          return json(res, 200, { ok: true, ...roster });
        }
      }
    }
    return serveStatic(req, res);
  } catch (error) {
    json(res, error.status || 500, { ok: false, error: error.message });
  }
});

server.listen(PORT, () => {
  console.log(`DroneWatch MVP running at http://localhost:${PORT}`);
  console.log(`Default region: ${DEFAULT_REGION_ID}`);
  console.log(`Configured CAP feeds: ${CONFIGURED_CAP_FEEDS.length}`);
  console.log(`OSINT JSON feeds: ${OSINT_JSON_FEEDS.length}`);
});
