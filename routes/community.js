const express = require('express');
const rateLimit = require('express-rate-limit');
const prisma = require('../lib/prisma');
const authMiddleware = require('../middleware/authMiddleware');
const { getIo } = require('../lib/realtime');

const router = express.Router();

const postLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many community posts. Please try again shortly.',
  },
});

const commentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many comments. Please try again shortly.',
  },
});

const idOk = (v) => typeof v === 'string' && v.length > 0 && v.length <= 40;
const cleanText = (v, max) =>
  typeof v === 'string' ? v.trim().replace(/\u0000/g, '').slice(0, max) : '';

const authorSelect = { id: true, name: true, avatar: true };

const postInclude = (viewerId) => ({
  author: { select: authorSelect },
  _count: { select: { likes: true, comments: true } },
  ...(viewerId
    ? {
        likes: {
          where: { userId: viewerId },
          select: { id: true },
          take: 1,
        },
      }
    : {}),
});

function shapePost(post) {
  return {
    id: post.id,
    content: post.content,
    mediaUrl: post.mediaUrl,
    mediaType: post.mediaType,
    createdAt: post.createdAt,
    updatedAt: post.updatedAt,
    author: post.author,
    likeCount: post._count?.likes || 0,
    commentCount: post._count?.comments || 0,
    likedByMe: Boolean(post.likes?.length),
  };
}

function emitCommunityEvent(event, payload) {
  try {
    const io = getIo();

    if (io) {
      io.emit(event, payload);
    }
  } catch (err) {
    console.error(`[community] ${event} emit failed:`, err.message);
  }
}

// Read-only public feed. Viewer identity is optional and never trusted from request body.
router.get('/feed', async (req, res, next) => {
  try {
    const limit = Math.min(
      30,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 15)
    );
    const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : null;

    const posts = await prisma.communityPost.findMany({
      take: limit + 1,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      include: postInclude(null),
    });

    const hasMore = posts.length > limit;
    const items = posts.slice(0, limit).map(shapePost);

    res.json({
      items,
      nextCursor: hasMore ? items[items.length - 1]?.id || null : null,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/posts/:postId/comments', async (req, res, next) => {
  try {
    if (!idOk(req.params.postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const limit = Math.min(
      50,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 25)
    );

    const comments = await prisma.communityComment.findMany({
      where: { postId: req.params.postId },
      take: limit,
      orderBy: { createdAt: 'asc' },
      include: { author: { select: authorSelect } },
    });

    res.json({ items: comments });
  } catch (err) {
    next(err);
  }
});

router.post('/posts', authMiddleware, postLimiter, async (req, res, next) => {
  try {
    const rawContent =
      typeof req.body?.content === 'string' ? req.body.content : '';

    if (rawContent.trim().length > 2000) {
      return res
        .status(400)
        .json({ error: 'Post text must be 2,000 characters or fewer.' });
    }

    const content = cleanText(rawContent, 2000);
    const mediaUrl =
      typeof req.body?.mediaUrl === 'string' ? req.body.mediaUrl.trim() : '';
    const mediaType =
      typeof req.body?.mediaType === 'string'
        ? req.body.mediaType.trim().toLowerCase()
        : '';

    if (!content && !mediaUrl) {
      return res.status(400).json({ error: 'Write something or attach media.' });
    }

    // Upload integration is intentionally separate. Only accept secure hosted media URLs, never data: URLs.
    if (mediaUrl) {
      let parsed;

      try {
        parsed = new URL(mediaUrl);
      } catch {
        return res.status(400).json({ error: 'Media URL is invalid.' });
      }

      if (
        parsed.protocol !== 'https:' ||
        !['image', 'video'].includes(mediaType)
      ) {
        return res
          .status(400)
          .json({ error: 'Media must be an HTTPS-hosted image or video.' });
      }

      if (mediaUrl.length > 2048) {
        return res.status(400).json({ error: 'Media URL is too long.' });
      }
    }

    const post = await prisma.communityPost.create({
      data: {
        authorId: req.user.id,
        content,
        mediaUrl: mediaUrl || null,
        mediaType: mediaUrl ? mediaType : null,
      },
      include: postInclude(req.user.id),
    });

    const shapedPost = shapePost(post);

    emitCommunityEvent('community:post_created', {
      post: { ...shapedPost, likedByMe: false },
    });

    res.status(201).json({ post: shapedPost });
  } catch (err) {
    next(err);
  }
});

router.delete('/posts/:postId', authMiddleware, async (req, res, next) => {
  try {
    const postId = req.params.postId;

    if (!idOk(postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const existing = await prisma.communityPost.findUnique({
      where: { id: postId },
      select: { authorId: true },
    });

    if (!existing) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    if (existing.authorId !== req.user.id) {
      return res
        .status(403)
        .json({ error: 'You can only delete your own posts.' });
    }

    await prisma.communityPost.delete({ where: { id: postId } });

    emitCommunityEvent('community:post_deleted', { postId });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.put('/posts/:postId/like', authMiddleware, async (req, res, next) => {
  try {
    const postId = req.params.postId;

    if (!idOk(postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const post = await prisma.communityPost.findUnique({
      where: { id: postId },
      select: { id: true },
    });

    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    const existing = await prisma.communityLike.findUnique({
      where: {
        postId_userId: { postId, userId: req.user.id },
      },
    });

    if (existing) {
      await prisma.communityLike.delete({
        where: {
          postId_userId: { postId, userId: req.user.id },
        },
      });

      const likeCount = await prisma.communityLike.count({
        where: { postId },
      });

      emitCommunityEvent('community:like_updated', { postId, likeCount });

      return res.json({ liked: false, likeCount });
    }

    await prisma.communityLike.create({
      data: { postId, userId: req.user.id },
    });

    const likeCount = await prisma.communityLike.count({
      where: { postId },
    });

    emitCommunityEvent('community:like_updated', { postId, likeCount });

    res.json({ liked: true, likeCount });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({ error: 'Like already exists.' });
    }

    next(err);
  }
});

router.post(
  '/posts/:postId/comments',
  authMiddleware,
  commentLimiter,
  async (req, res, next) => {
    try {
      const postId = req.params.postId;
      const content = cleanText(req.body?.content, 1000);

      if (!idOk(postId)) {
        return res.status(400).json({ error: 'Invalid post ID' });
      }

      if (!content) {
        return res.status(400).json({ error: 'Comment cannot be empty.' });
      }

      if (content.length > 1000) {
        return res
          .status(400)
          .json({ error: 'Comment must be 1,000 characters or fewer.' });
      }

      const exists = await prisma.communityPost.findUnique({
        where: { id: postId },
        select: { id: true },
      });

      if (!exists) {
        return res.status(404).json({ error: 'Post not found.' });
      }

      const comment = await prisma.communityComment.create({
        data: { postId, authorId: req.user.id, content },
        include: { author: { select: authorSelect } },
      });

      const commentCount = await prisma.communityComment.count({
        where: { postId },
      });

      emitCommunityEvent('community:comment_created', {
        postId,
        comment,
        commentCount,
      });

      res.status(201).json({ comment, commentCount });
    } catch (err) {
      next(err);
    }
  }
);

router.put('/users/:userId/follow', authMiddleware, async (req, res, next) => {
  try {
    const targetId = Number(req.params.userId);

    if (!Number.isSafeInteger(targetId) || targetId <= 0) {
      return res.status(400).json({ error: 'Invalid user ID.' });
    }

    if (targetId === req.user.id) {
      return res.status(400).json({ error: 'You cannot follow yourself.' });
    }

    const target = await prisma.user.findUnique({
      where: { id: targetId },
      select: { id: true },
    });

    if (!target) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const where = {
      followerId_followingId: {
        followerId: req.user.id,
        followingId: targetId,
      },
    };

    const existing = await prisma.communityFollow.findUnique({ where });

    if (existing) {
      await prisma.communityFollow.delete({ where });
      return res.json({ following: false });
    }

    await prisma.communityFollow.create({
      data: { followerId: req.user.id, followingId: targetId },
    });

    res.json({ following: true });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({ error: 'Already following this user.' });
    }

    next(err);
  }
});

module.exports = router;
