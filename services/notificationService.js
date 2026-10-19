// services/notificationService.js
//
// One place that creates notifications. Saving + pushing happen together:
//   1) row is written to the database (source of truth, survives offline users)
//   2) the same notification is pushed live to that user's private socket room
//
// Safe to call from anywhere: createNotification() never throws, so a failing
// notification can never break signup, rewards, or any other main flow.

const prisma = require('../lib/prisma');
const { emitToUser } = require('../lib/realtime');

const MAX_TITLE = 120;
const MAX_BODY = 500;
const PAGE_DEFAULT = 30;
const PAGE_MAX = 50;

function toPublic(row) {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    body: row.body,
    data: row.data ?? null,
    read: row.readAt !== null && row.readAt !== undefined,
    readAt: row.readAt ? new Date(row.readAt).toISOString() : null,
    createdAt: new Date(row.createdAt).toISOString(),
  };
}

function clip(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

/**
 * Create + push. Returns the public notification, or null if it was a duplicate
 * (same dedupeKey) or something failed.
 */
async function createNotification(userId, { type = 'system', title, body, data = null, dedupeKey = null } = {}) {
  try {
    const uid = Number(userId);
    if (!Number.isInteger(uid) || uid <= 0) return null;

    const cleanTitle = clip(title, MAX_TITLE);
    const cleanBody = clip(body, MAX_BODY);
    if (!cleanTitle || !cleanBody) return null;

    let row;
    try {
      row = await prisma.notification.create({
        data: {
          userId: uid,
          type: clip(type, 40) || 'system',
          title: cleanTitle,
          body: cleanBody,
          data: data ?? undefined,
          dedupeKey: dedupeKey ? clip(dedupeKey, 120) : null,
        },
      });
    } catch (err) {
      if (err?.code === 'P2002') return null; // dedupeKey already used -> already notified
      throw err;
    }

    const payload = toPublic(row);
    emitToUser(uid, 'notification:new', payload);
    return payload;
  } catch (err) {
    console.error('[notifications] create failed:', err.message);
    return null;
  }
}

async function listForUser(userId, { limit, cursor } = {}) {
  const take = Math.min(Math.max(parseInt(limit, 10) || PAGE_DEFAULT, 1), PAGE_MAX);

  const rows = await prisma.notification.findMany({
    where: { userId },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: take + 1,
    ...(cursor ? { cursor: { id: String(cursor) }, skip: 1 } : {}),
  });

  const hasMore = rows.length > take;
  const page = hasMore ? rows.slice(0, take) : rows;

  return {
    notifications: page.map(toPublic),
    nextCursor: hasMore ? page[page.length - 1].id : null,
  };
}

async function unreadCount(userId) {
  return prisma.notification.count({ where: { userId, readAt: null } });
}

/** Marks ONE notification read — only if it belongs to this user. */
async function markRead(userId, id) {
  const result = await prisma.notification.updateMany({
    where: { id: String(id), userId, readAt: null },
    data: { readAt: new Date() },
  });
  const unread = await unreadCount(userId);
  // Tell the user's OTHER open tabs/devices instantly.
  emitToUser(userId, 'notification:read', { id: String(id), unreadCount: unread });
  return { updated: result.count, unreadCount: unread };
}

async function markAllRead(userId) {
  const result = await prisma.notification.updateMany({
    where: { userId, readAt: null },
    data: { readAt: new Date() },
  });
  emitToUser(userId, 'notification:read-all', { unreadCount: 0 });
  return { updated: result.count, unreadCount: 0 };
}

module.exports = {
  createNotification,
  listForUser,
  unreadCount,
  markRead,
  markAllRead,
  toPublic,
};
