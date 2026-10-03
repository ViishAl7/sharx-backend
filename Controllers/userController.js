// FIX: was creating its own `new PrismaClient()` — now shares one client
// with the rest of the app via lib/prisma.js (see that file for why).
const prisma = require("../lib/prisma");

// GET /user/profile
const getProfile = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        name: true,
        email: true,
        avatar: true,
        score: true,
        matches: {
          orderBy: { createdAt: "desc" },
          take: 10,
          select: {
            id: true,
            result: true,
            score: true,
            createdAt: true,
          },
        },
      },
    });

    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("getProfile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// PUT /user/profile — update name and/or avatar
const updateProfile = async (req, res) => {
  const { name, avatar } = req.body;

  // FIX: previously an empty PUT body (name and avatar both missing/
  // undefined) would silently fall through to prisma.user.update()
  // with an empty `data: {}` object. Prisma allows that (it's a no-op
  // update), but it's a confusing "successful" response for a request
  // that changed nothing. Now we reject that case explicitly.
  if (name === undefined && avatar === undefined) {
    return res.status(400).json({ message: "Nothing to update — provide name and/or avatar" });
  }

  // FIX: previously an explicit empty string for `name` (e.g. someone
  // clearing the field in a form and submitting) was falsy, so
  // `...(name && { name })` silently dropped it instead of either
  // rejecting it or applying it. Empty name is invalid, not "no change".
  if (name !== undefined && (typeof name !== "string" || name.trim().length === 0)) {
    return res.status(400).json({ message: "Name cannot be empty" });
  }

  try {
    const data = {};
    if (name !== undefined) data.name = name.trim();
    if (avatar !== undefined) data.avatar = avatar;

    const updated = await prisma.user.update({
      where: { id: req.user.id },
      data,
      select: { id: true, name: true, email: true, avatar: true, score: true },
    });
    res.json(updated);
  } catch (err) {
    // FIX: prisma.user.update() throws P2025 ("Record to update not
    // found") if the user id from the JWT no longer exists (e.g. the
    // account was deleted after the token was issued). That used to
    // fall through to a generic 500 instead of an accurate 404.
    if (err.code === "P2025") {
      return res.status(404).json({ message: "User not found" });
    }
    console.error("updateProfile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// GET /user/history — game history
const getHistory = async (req, res) => {
  try {
    const matches = await prisma.match.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: "desc" },
      select: { id: true, result: true, score: true, createdAt: true },
    });
    res.json(matches);
  } catch (err) {
    console.error("getHistory error:", err);
    res.status(500).json({ message: "Server error" });
  }
};
// POST /user/games/:gameId/play
// Records that the authenticated user played a game.
const recordGamePlay = async (req, res) => {
  const { gameId } = req.params;
  const { gameName, playSeconds = 0 } = req.body || {};

  if (!gameId || typeof gameId !== "string" || gameId.length > 200) {
    return res.status(400).json({ message: "Invalid gameId" });
  }

  const seconds = Number(playSeconds);

  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 86400) {
    return res.status(400).json({ message: "Invalid playSeconds" });
  }

  if (
    gameName !== undefined &&
    gameName !== null &&
    (typeof gameName !== "string" || gameName.length > 300)
  ) {
    return res.status(400).json({ message: "Invalid gameName" });
  }

  try {
    const history = await prisma.gameHistory.upsert({
      where: {
        userId_gameId: {
          userId: req.user.id,
          gameId,
        },
      },
      create: {
        userId: req.user.id,
        gameId,
        gameName: typeof gameName === "string" ? gameName.trim() : null,
        playCount: 1,
        totalPlaySeconds: seconds,
        lastPlayedAt: new Date(),
      },
      update: {
        ...(typeof gameName === "string" &&
          gameName.trim() && {
            gameName: gameName.trim(),
          }),
        playCount: {
          increment: 1,
        },
        totalPlaySeconds: {
          increment: seconds,
        },
        lastPlayedAt: new Date(),
      },
    });

    res.json(history);
  } catch (err) {
    console.error("recordGamePlay error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// GET /user/games/history
const getGameHistory = async (req, res) => {
  try {
    const history = await prisma.gameHistory.findMany({
      where: { userId: req.user.id },
      orderBy: { lastPlayedAt: "desc" },
      take: 100,
      select: {
        id: true,
        gameId: true,
        gameName: true,
        lastPlayedAt: true,
        playCount: true,
        totalPlaySeconds: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    res.json(history);
  } catch (err) {
    console.error("getGameHistory error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// GET /user/games/:gameId/progress
const getGameProgress = async (req, res) => {
  const { gameId } = req.params;

  if (!gameId || typeof gameId !== "string" || gameId.length > 200) {
    return res.status(400).json({ message: "Invalid gameId" });
  }

  try {
    const progress = await prisma.gameProgress.findUnique({
      where: {
        userId_gameId: {
          userId: req.user.id,
          gameId,
        },
      },
      select: {
        gameId: true,
        progress: true,
        score: true,
        level: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!progress) {
      return res.status(404).json({ message: "No saved progress found" });
    }

    res.json(progress);
  } catch (err) {
    console.error("getGameProgress error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// PUT /user/games/:gameId/progress
const saveGameProgress = async (req, res) => {
  const { gameId } = req.params;
  const { progress, score, level } = req.body || {};

  if (!gameId || typeof gameId !== "string" || gameId.length > 200) {
    return res.status(400).json({ message: "Invalid gameId" });
  }

  if (
    progress === undefined ||
    progress === null ||
    typeof progress !== "object" ||
    Array.isArray(progress)
  ) {
    return res.status(400).json({ message: "progress must be a JSON object" });
  }

  if (
    score !== undefined &&
    score !== null &&
    (!Number.isInteger(score) || score < 0)
  ) {
    return res.status(400).json({ message: "Invalid score" });
  }

  if (
    level !== undefined &&
    level !== null &&
    (!Number.isInteger(level) || level < 0)
  ) {
    return res.status(400).json({ message: "Invalid level" });
  }

  try {
    const saved = await prisma.gameProgress.upsert({
      where: {
        userId_gameId: {
          userId: req.user.id,
          gameId,
        },
      },
      create: {
        userId: req.user.id,
        gameId,
        progress,
        score: score ?? null,
        level: level ?? null,
      },
      update: {
        progress,
        ...(score !== undefined && { score: score ?? null }),
        ...(level !== undefined && { level: level ?? null }),
      },
      select: {
        gameId: true,
        progress: true,
        score: true,
        level: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    res.json(saved);
  } catch (err) {
    console.error("saveGameProgress error:", err);
    res.status(500).json({ message: "Server error" });
  }
};
module.exports = {
  getProfile,
  updateProfile,
  getHistory,
  recordGamePlay,
  getGameHistory,
  getGameProgress,
  saveGameProgress,
};