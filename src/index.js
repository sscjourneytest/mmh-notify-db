/**
 * MOCK MATRIX HUB — Notification Worker
 * ---------------------------------------------------------
 * Endpoints:
 *   POST /api/notify/subscribe   { subscription, user_id? }   -> save push subscription
 *   POST /api/notify/send        { title, body, url, icon? }  -> push to everyone (admin-only)
 *   GET  /api/notify/list        ?since=<id>                  -> notification history (for bell + page)
 *   GET  /api/notify/vapid-key                                -> public key for frontend subscribe()
 *
 * Bindings expected (set in wrangler.toml):
 *   DB            -> D1 database
 *   VAPID_PUBLIC  -> secret: VAPID public key (also fine as plain var, it's public)
 *   VAPID_PRIVATE -> secret: VAPID private key
 *   VAPID_SUBJECT -> e.g. "mailto:you@yourdomain.com"
 *   ADMIN_SECRET  -> secret: shared secret admin page must send to allow sending notifications
 */

import { sendWebPush } from "./push.js";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*", // tighten to your domain once live, e.g. "https://mockmatrixhub.com"
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      if (url.pathname === "/api/notify/vapid-key" && request.method === "GET") {
        return json({ publicKey: env.VAPID_PUBLIC });
      }

      if (url.pathname === "/api/notify/subscribe" && request.method === "POST") {
        return await handleSubscribe(request, env);
      }

      if (url.pathname === "/api/notify/send" && request.method === "POST") {
        return await handleSend(request, env);
      }

      if (url.pathname === "/api/notify/list" && request.method === "GET") {
        return await handleList(request, env);
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: "Internal error", detail: String(err) }, 500);
    }
  },
};

// ------------------------------------------------------------------
// POST /api/notify/subscribe
// Saves (or updates) a push subscription coming from the browser.
// ------------------------------------------------------------------
async function handleSubscribe(request, env) {
  const data = await request.json();
  const sub = data.subscription;

  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
    return json({ error: "Invalid subscription object" }, 400);
  }

  await env.DB.prepare(
    `INSERT INTO subscriptions (endpoint, p256dh, auth, user_id, created_at, last_seen_at)
     VALUES (?, ?, ?, ?, unixepoch(), unixepoch())
     ON CONFLICT(endpoint) DO UPDATE SET
        p256dh = excluded.p256dh,
        auth = excluded.auth,
        user_id = excluded.user_id,
        last_seen_at = unixepoch()`
  )
    .bind(sub.endpoint, sub.keys.p256dh, sub.keys.auth, data.user_id || null)
    .run();

  return json({ ok: true });
}

// ------------------------------------------------------------------
// POST /api/notify/send   (admin only — checks X-Admin-Secret header)
// Saves the notification, then pushes it to every saved subscription.
// ------------------------------------------------------------------
async function handleSend(request, env) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!adminSecret || adminSecret !== env.ADMIN_SECRET) {
    return json({ error: "Unauthorized" }, 401);
  }

  const { title, body, url, icon } = await request.json();
  if (!title || !body) {
    return json({ error: "title and body are required" }, 400);
  }

  const targetUrl = url || "/";

  // 1. Save the notification record first (this is what the bell/history page reads).
  const insertResult = await env.DB.prepare(
    `INSERT INTO notifications (title, body, url, icon, created_at) VALUES (?, ?, ?, ?, unixepoch())`
  )
    .bind(title, body, targetUrl, icon || null)
    .run();

  const notificationId = insertResult.meta.last_row_id;

  // 2. Pull every subscription and push to each one.
  const { results: subs } = await env.DB.prepare(`SELECT * FROM subscriptions`).all();

  let sent = 0;
  let failed = 0;
  const deadEndpoints = [];

  const payload = JSON.stringify({
    title,
    body,
    url: targetUrl,
    icon: icon || "/icons/icon-192.png",
    notificationId,
  });

  for (const row of subs) {
    const subscription = {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    };

    try {
      const res = await sendWebPush(subscription, payload, {
        publicKey: env.VAPID_PUBLIC,
        privateKey: env.VAPID_PRIVATE,
        subject: env.VAPID_SUBJECT,
      });

      // 410 Gone / 404 Not Found = subscription is dead (user uninstalled/blocked), clean it up.
      if (res.status === 410 || res.status === 404) {
        deadEndpoints.push(row.endpoint);
        failed++;
      } else if (res.status >= 200 && res.status < 300) {
        sent++;
      } else {
        failed++;
      }
    } catch (e) {
      console.error("push failed for", row.endpoint, e);
      failed++;
    }
  }

  // 3. Clean up dead subscriptions so future sends don't waste time on them.
  for (const endpoint of deadEndpoints) {
    await env.DB.prepare(`DELETE FROM subscriptions WHERE endpoint = ?`).bind(endpoint).run();
  }

  await env.DB.prepare(`UPDATE notifications SET sent_count = ?, failed_count = ? WHERE id = ?`)
    .bind(sent, failed, notificationId)
    .run();

  return json({ ok: true, notificationId, sent, failed, totalSubscriptions: subs.length });
}

// ------------------------------------------------------------------
// GET /api/notify/list?since=<id>&limit=20
// Returns notification history, newest first. Used by bell badge + history page.
// ------------------------------------------------------------------
async function handleList(request, env) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "20", 10), 100);

  const { results } = await env.DB.prepare(
    `SELECT id, title, body, url, icon, created_at FROM notifications ORDER BY id DESC LIMIT ?`
  )
    .bind(limit)
    .all();

  return json({ notifications: results });
}
