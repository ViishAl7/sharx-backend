const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

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
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// PUT /user/profile — name ya avatar update karo
const updateProfile = async (req, res) => {
  const { name, avatar } = req.body;
  try {
    const updated = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        ...(name && { name }),
        ...(avatar && { avatar }),
      },
      select: { id: true, name: true, email: true, avatar: true, score: true },
    });
    res.json(updated);
  } catch (err) {
    console.error(err);
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
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

module.exports = { getProfile, updateProfile, getHistory };