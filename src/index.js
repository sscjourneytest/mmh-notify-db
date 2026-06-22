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
  async fetch(request, env, ctx) {
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
        return await handleSend(request, env, ctx);
      }

      if (url.pathname === "/api/notify/status" && request.method === "GET") {
        return await handleStatus(request, env);
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
// Saves the notification immediately, responds right away with the
// notificationId, then keeps pushing to subscribers IN BATCHES in the
// background (via ctx.waitUntil) so the admin's request doesn't have
// to wait for thousands of pushes, and so we never run too much
// crypto work inside a single execution (avoids CPU-time limits).
// ------------------------------------------------------------------
const BATCH_SIZE = 5; // how many pushes to send per batch
const BATCH_DELAY_MS = 300; // pause between batches, gives the Worker breathing room

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function handleSend(request, env, ctx) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!adminSecret || adminSecret !== env.ADMIN_SECRET) {
    return json({ error: "Unauthorized" }, 401);
  }

  const { title, body, url, icon } = await request.json();
  if (!title || !body) {
    return json({ error: "title and body are required" }, 400);
  }

  const targetUrl = url || "/";

  // 1. Save the notification record first (this is what the bell/history page reads,
  //    and it shows up immediately even before any push has gone out).
  const insertResult = await env.DB.prepare(
    `INSERT INTO notifications (title, body, url, icon, created_at, send_status) VALUES (?, ?, ?, ?, unixepoch(), 'sending')`
  )
    .bind(title, body, targetUrl, icon || null)
    .run();

  const notificationId = insertResult.meta.last_row_id;

  // 2. Count subscribers up front so we can respond instantly with a total.
  const { results: countRows } = await env.DB.prepare(
    `SELECT COUNT(*) as total FROM subscriptions`
  ).all();
  const totalSubscriptions = countRows[0]?.total || 0;

  // 3. Kick off the actual batched sending as background work — this continues
  //    running even after we return the response below.
  ctx.waitUntil(
    processSendInBatches(env, notificationId, { title, body, url: targetUrl, icon })
  );

  // 4. Respond immediately — admin page can poll /api/notify/status?id=... for progress.
  return json({
    ok: true,
    notificationId,
    totalSubscriptions,
    status: "sending",
    message: `Sending to ${totalSubscriptions} subscriber(s) in the background.`,
  });
}

async function processSendInBatches(env, notificationId, { title, body, url, icon }) {
  const payload = JSON.stringify({
    title,
    body,
    url,
    icon: icon || "/icons/icon-192.png",
    notificationId,
  });

  let sent = 0;
  let failed = 0;
  let offset = 0;
  const allDeadEndpoints = [];

  while (true) {
    const { results: batch } = await env.DB.prepare(
      `SELECT * FROM subscriptions LIMIT ? OFFSET ?`
    )
      .bind(BATCH_SIZE, offset)
      .all();

    if (batch.length === 0) break; // no more subscribers left

    for (const row of batch) {
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

        if (res.status === 410 || res.status === 404) {
          allDeadEndpoints.push(row.endpoint);
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

    // Update progress after every batch, so the admin page can poll live counts.
    await env.DB.prepare(
      `UPDATE notifications SET sent_count = ?, failed_count = ? WHERE id = ?`
    )
      .bind(sent, failed, notificationId)
      .run();

    offset += BATCH_SIZE; // move to next page of subscriptions; we delete dead ones only after the loop finishes, so offsets stay simple and correct
    await sleep(BATCH_DELAY_MS); // brief pause before next batch
  }

  // Clean up every dead subscription found across all batches, now that pagination is done.
  for (const endpoint of allDeadEndpoints) {
    await env.DB.prepare(`DELETE FROM subscriptions WHERE endpoint = ?`).bind(endpoint).run();
  }

  // Mark as fully complete.
  await env.DB.prepare(`UPDATE notifications SET send_status = 'done' WHERE id = ?`)
    .bind(notificationId)
    .run();
}

// ------------------------------------------------------------------
// GET /api/notify/status?id=<notificationId>
// Lets the admin page poll how a send is progressing.
// ------------------------------------------------------------------
async function handleStatus(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  if (!id) return json({ error: "id is required" }, 400);

  const { results } = await env.DB.prepare(
    `SELECT id, title, sent_count, failed_count, send_status FROM notifications WHERE id = ?`
  )
    .bind(id)
    .all();

  if (results.length === 0) return json({ error: "Not found" }, 404);

  return json(results[0]);
}

// ------------------------------------------------------------------
// GET /api/notify/list?limit=10&before_id=<id>
// Returns notification history, newest first.
//   - No before_id  -> first page (latest N notifications)
//   - before_id=X   -> next page (N notifications older than id X)
// Used by both the bell badge (small limit, no before_id) and the
// full history page (paginated with before_id for "Load More").
// ------------------------------------------------------------------
async function handleList(request, env) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "20", 10), 100);
  const beforeId = url.searchParams.get("before_id");

  let results;
  if (beforeId) {
    ({ results } = await env.DB.prepare(
      `SELECT id, title, body, url, icon, created_at FROM notifications WHERE id < ? ORDER BY id DESC LIMIT ?`
    )
      .bind(parseInt(beforeId, 10), limit)
      .all());
  } else {
    ({ results } = await env.DB.prepare(
      `SELECT id, title, body, url, icon, created_at FROM notifications ORDER BY id DESC LIMIT ?`
    )
      .bind(limit)
      .all());
  }

  const hasMore = results.length === limit; // if we got a full page, there might be more

  return json({ notifications: results, hasMore });
}

