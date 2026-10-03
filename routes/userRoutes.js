const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");

const {
  getProfile,
  updateProfile,
  getHistory,
  recordGamePlay,
  getGameHistory,
  getGameProgress,
  saveGameProgress,
} = require("../Controllers/userController");

// Existing user APIs
router.get("/profile", authMiddleware, getProfile);
router.put("/profile", authMiddleware, updateProfile);
router.get("/history", authMiddleware, getHistory);

// Persistent game history
router.post("/games/:gameId/play", authMiddleware, recordGamePlay);
router.get("/games/history", authMiddleware, getGameHistory);

// Persistent game progress
router.get("/games/:gameId/progress", authMiddleware, getGameProgress);
router.put("/games/:gameId/progress", authMiddleware, saveGameProgress);

module.exports = router;