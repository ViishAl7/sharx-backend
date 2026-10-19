// routes/notifications.js — mounted at /notifications
//
// Every route runs behind authMiddleware. The user is ALWAYS req.user.id
// (from the verified JWT). There is no userId in any URL, query or body, so
// one user can never read or change another user's notifications.

const express = require('express');
const rateLimit = require('express-rate-limit');
const authMiddleware = require('../middleware/authMiddleware');
const service = require('../services/notificationService');

const router = express.Router();

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please slow down.' },
});

router.use(limiter);
router.use(authMiddleware);

// GET /notifications?limit=30&cursor=<id>
router.get('/', async (req, res) => {
  try {
    const [page, unreadCount] = await Promise.all([
      service.listForUser(req.user.id, { limit: req.query.limit, cursor: req.query.cursor }),
      service.unreadCount(req.user.id),
    ]);
    res.json({ ...page, unreadCount });
  } catch (err) {
    console.error('GET /notifications error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /notifications/unread-count
router.get('/unread-count', async (req, res) => {
  try {
    res.json({ unreadCount: await service.unreadCount(req.user.id) });
  } catch (err) {
    console.error('GET /notifications/unread-count error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /notifications/read-all   (declared BEFORE /:id/read)
router.post('/read-all', async (req, res) => {
  try {
    res.json(await service.markAllRead(req.user.id));
  } catch (err) {
    console.error('POST /notifications/read-all error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /notifications/:id/read
router.post('/:id/read', async (req, res) => {
  const id = req.params.id;
  if (typeof id !== 'string' || id.length === 0 || id.length > 60) {
    return res.status(400).json({ message: 'Invalid notification id' });
  }
  try {
    res.json(await service.markRead(req.user.id, id));
  } catch (err) {
    console.error('POST /notifications/:id/read error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /notifications/test — LOCAL TESTING ONLY.
// Off unless ENABLE_TEST_NOTIFICATIONS=true. Sends a notification to YOURSELF
// (the token owner) so you can watch the bell update live.
if (process.env.ENABLE_TEST_NOTIFICATIONS === 'true') {
  router.post('/test', async (req, res) => {
    const created = await service.createNotification(req.user.id, {
      type: 'system',
      title: 'Test notification',
      body: `Live delivery works. Sent at ${new Date().toLocaleTimeString()}.`,
    });
    res.json({ sent: Boolean(created) });
  });
}

module.exports = router;
