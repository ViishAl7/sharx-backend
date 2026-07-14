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

module.exports = { getProfile, updateProfile, getHistory };
