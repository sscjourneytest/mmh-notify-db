-- ============================================================
-- MOCK MATRIX HUB — Notification System D1 Schema
-- Run this once via: wrangler d1 execute mmh-notify-db --file=./schema.sql
-- ============================================================

-- Stores one row per browser/device that allowed notifications.
-- "endpoint" is the unique push address given by the browser (Chrome/Firefox push service etc).
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,        -- public key piece of the subscription (required for encryption)
    auth TEXT NOT NULL,          -- auth secret piece of the subscription (required for encryption)
    user_id TEXT,                -- optional: Supabase user id, if logged in when they subscribed
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Stores every notification you (admin) ever sent.
-- This doubles as: (1) source for push delivery, (2) source for the in-site notification history page.
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '/',   -- where tapping the notification should take the user
    icon TEXT,                        -- optional custom icon url, falls back to default app icon
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    sent_count INTEGER NOT NULL DEFAULT 0,   -- how many subscriptions it was pushed to
    failed_count INTEGER NOT NULL DEFAULT 0,  -- how many push deliveries failed (dead subscriptions)
    send_status TEXT NOT NULL DEFAULT 'done'  -- 'sending' while batches are still going, 'done' once finished
);

CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
