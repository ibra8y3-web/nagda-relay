// NAGDA relay on Cloudflare Workers + one Durable Object (SQLite-backed, free plan). Apache-2.0.
// One Durable Object ("main") holds all alerts. A Durable Object runs one instance, so the helper cap is atomic;
// we also queue requests so awaits cannot interleave two accepts.
import { DurableObject } from 'cloudflare:workers';
// NAGDA relay core. Pure request logic shared by the Node server and the Cloudflare Worker. Apache-2.0.
// store: async { get(id), put(alert), all() }  ->  alerts are plain JSON objects.
const wc = globalThis.crypto;
const MAX_RESPONDERS = 3;
const EXPIRE_MS = 12 * 3600 * 1000;
const TYPES = ['URGENT', 'MEDICAL', 'CAR_ACCIDENT', 'FIRE', 'THREAT', 'MISSING', 'ROADSIDE', 'HUMANITARIAN', 'ELDERLY_DISABLED', 'OTHER'];
const PRIO = { URGENT: 5, MEDICAL: 5, FIRE: 5, THREAT: 5, CAR_ACCIDENT: 4, MISSING: 4, ELDERLY_DISABLED: 3, ROADSIDE: 2, HUMANITARIAN: 2, OTHER: 1 };
const TERMINAL = new Set(['RESOLVED', 'CANCELLED', 'EXPIRED']);
const NEXT = {
  ACTIVE: ['ACCEPTED', 'RESOLVED', 'CANCELLED', 'EXPIRED'],
  ACCEPTED: ['RESPONDING', 'RESOLVED', 'CANCELLED', 'EXPIRED'],
  RESPONDING: ['ARRIVED', 'RESOLVED', 'CANCELLED', 'EXPIRED'],
  ARRIVED: ['RESOLVED', 'CANCELLED'],
};
const MAX_TRACK = 300;

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await wc.subtle.digest('SHA-256', new TextEncoder().encode(s)));
const randomHex = (n) => hex(wc.getRandomValues(new Uint8Array(n)));
const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const round = (v) => Math.round(v * 100) / 100;                 // ~1 km: public views never get an exact location
const validLat = (v) => typeof v === 'number' && v >= -90 && v <= 90;
const validLon = (v) => typeof v === 'number' && v >= -180 && v <= 180;
const km = (a, b, c, d) => { const R = 6371, r = Math.PI / 180, dl = (c - a) * r, dn = (d - b) * r; const x = Math.sin(dl / 2) ** 2 + Math.cos(a * r) * Math.cos(c * r) * Math.sin(dn / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(x)); };
const pub = (a) => ({ id: a.id, type: a.type, priority: a.priority, status: a.status, latitude: round(a.last.latitude), longitude: round(a.last.longitude), approximate: true, createdAt: a.createdAt, responders: a.responders.length, maxResponders: MAX_RESPONDERS });
const R = (code, json) => ({ code, json });

function createCore({ store, now = () => Date.now() }) {
  const move = (a, to) => { if (!(NEXT[a.status] || []).includes(to)) return false; a.status = to; a.updatedAt = now(); a.events.push({ t: now(), k: to }); return true; };
  async function expire(a) { if (a && !TERMINAL.has(a.status) && now() - a.updatedAt > EXPIRE_MS) { a.status = 'EXPIRED'; a.updatedAt = now(); a.events.push({ t: now(), k: 'EXPIRED' }); await store.put(a); } return a; }

  // req: { method, pathname, query(URLSearchParams), idempotencyKey, bearer, body(object|null) }
  return async function handle(req) {
    const p = req.pathname.split('/').filter(Boolean);
    if (req.method === 'GET' && req.pathname === '/health') return R(200, { ok: true });
    if (p[0] !== 'v1' || p[1] !== 'emergencies') return R(404, { error: 'not_found' });

    if (req.method === 'POST' && p.length === 2) {
      const key = req.idempotencyKey;
      if (!key || !/^[0-9a-fA-F-]{8,64}$/.test(key)) return R(400, { error: 'idempotency_key_required' });
      const existing = await store.get(key);
      if (existing) return R(200, { id: existing.id, status: existing.status, replay: true });      // owner token is never re-sent
      const b = req.body || {};
      if (!TYPES.includes(b.type) || !validLat(b.latitude) || !validLon(b.longitude) || (b.latitude === 0 && b.longitude === 0)) return R(400, { error: 'invalid_body' });
      const token = randomHex(24), t = now();
      const loc = { latitude: b.latitude, longitude: b.longitude, accuracy: b.accuracy || null, t };
      await store.put({ id: key, ownerHash: await sha(token), type: b.type, priority: PRIO[b.type], status: 'ACTIVE', description: String(b.description || '').slice(0, 500),
        createdAt: t, updatedAt: t, last: loc, track: [loc], responders: [], events: [{ t, k: 'ACTIVE' }] });
      return R(201, { id: key, status: 'ACTIVE', ownerToken: token });
    }

    if (req.method === 'GET' && p.length === 3 && p[2] === 'nearby') {
      const lat = parseFloat(req.query.get('lat')), lon = parseFloat(req.query.get('lon')), r = Math.min(parseFloat(req.query.get('radius_km') || '5'), 50);
      if (!validLat(lat) || !validLon(lon)) return R(400, { error: 'invalid_query' });
      const all = [];
      for (const a of await store.all()) { await expire(a); if (!TERMINAL.has(a.status) && km(lat, lon, a.last.latitude, a.last.longitude) <= r) all.push(a); }
      all.sort((x, y) => y.priority - x.priority || y.createdAt - x.createdAt);
      return R(200, { alerts: all.slice(0, 50).map(pub) });
    }

    const a = await expire(await store.get(p[2]));
    if (!a) return R(404, { error: 'not_found' });
    const owner = eq(await sha(req.bearer || ''), a.ownerHash);
    const action = p[3];

    if (req.method === 'GET' && !action) return R(200, owner ? { ...pub(a), exact: a.last, description: a.description, events: a.events } : pub(a));
    if (req.method === 'GET' && action === 'tracking') {
      const dev = req.query.get('device') || '';
      if (!owner && !a.responders.includes(dev)) return R(403, { error: 'forbidden' });   // device id is self-declared, not strong authentication
      return R(200, { status: a.status, track: a.track.slice(-200) });
    }
    if (req.method !== 'POST') return R(405, { error: 'method' });
    const b = req.body || {};

    if (action === 'accept') {
      const dev = String(b.deviceId || '');
      if (!/^[0-9a-fA-F-]{8,64}$/.test(dev)) return R(400, { error: 'device_id_required' });
      if (TERMINAL.has(a.status)) return R(409, { error: 'closed', status: a.status });
      if (a.responders.includes(dev)) return R(200, { accepted: true, replay: true });
      if (a.responders.length >= MAX_RESPONDERS) return R(409, { error: 'full' });
      a.responders.push(dev); if (a.status === 'ACTIVE') move(a, 'ACCEPTED'); a.updatedAt = now(); await store.put(a);
      return R(200, { accepted: true, exact: a.last });                                  // exact location only after a successful accept
    }
    if (!owner) return R(403, { error: 'forbidden' });
    if (action === 'locations') {
      if (TERMINAL.has(a.status)) return R(409, { error: 'closed' });
      if (!validLat(b.latitude) || !validLon(b.longitude)) return R(400, { error: 'invalid_body' });
      const t = Number.isFinite(b.timestamp) ? b.timestamp : now();
      if (t <= a.last.t) return R(202, { ignored: 'older' });
      a.last = { latitude: b.latitude, longitude: b.longitude, accuracy: b.accuracy || null, t }; a.track.push(a.last);
      if (a.track.length > MAX_TRACK) a.track.splice(0, a.track.length - MAX_TRACK);
      a.updatedAt = now(); await store.put(a);
      return R(202, { ok: true });
    }
    if (action === 'cancel' || action === 'resolve') {
      const to = action === 'cancel' ? 'CANCELLED' : 'RESOLVED';
      if (a.status === to) return R(200, { status: a.status, replay: true });
      if (!move(a, to)) return R(409, { error: 'bad_transition', status: a.status });
      await store.put(a); return R(200, { status: a.status });
    }
    if (action === 'status' && ['RESPONDING', 'ARRIVED'].includes(b.status)) {
      if (!move(a, b.status)) return R(409, { error: 'bad_transition', status: a.status });
      await store.put(a); return R(200, { status: a.status });
    }
    return R(404, { error: 'not_found' });
  };
}


const HEAD = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
const reply = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: HEAD });
const KEEP_CLOSED_MS = 7 * 24 * 3600 * 1000;

export class Relay extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const storage = ctx.storage;
    const store = {
      async get(id) { return (await storage.get('a:' + id)) ?? null; },
      async put(a) { await storage.put('a:' + a.id, a); },
      async all() {
        const out = [], stale = [];
        for (const [k, a] of await storage.list({ prefix: 'a:' })) {
          if (['RESOLVED', 'CANCELLED', 'EXPIRED'].includes(a.status) && Date.now() - a.updatedAt > KEEP_CLOSED_MS) stale.push(k); else out.push(a);
        }
        if (stale.length) await storage.delete(stale.slice(0, 128));
        return out;
      },
    };
    this.core = createCore({ store });
    this.queue = Promise.resolve();
  }

  async fetch(request) {
    const url = new URL(request.url);
    let body = null;
    if (request.method === 'POST') {
      const text = await request.text();
      if (text.length > 20000) return reply(413, { error: 'too large' });
      try { body = text ? JSON.parse(text) : {}; } catch (e) { return reply(400, { error: 'bad json' }); }
    }
    const req = { method: request.method, pathname: url.pathname, query: url.searchParams, idempotencyKey: request.headers.get('idempotency-key'),
      bearer: (request.headers.get('authorization') || '').replace(/^Bearer /, ''), body };
    const run = this.queue.then(() => this.core(req));
    this.queue = run.catch(() => {});
    try { const r = await run; return reply(r.code, r.json); } catch (e) { return reply(500, { error: 'error' }); }
  }
}

export default {
  async fetch(request, env) {
    return env.RELAY.get(env.RELAY.idFromName('main')).fetch(request);
  },
};
