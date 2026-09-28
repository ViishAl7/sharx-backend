const crypto = require("crypto");

const MILESTONE_SECONDS = 60 * 60;

// A heartbeat can be delayed by browser throttling/network lag.
// Never credit more than this amount of time from one heartbeat.
const HEARTBEAT_GRACE_SECONDS = 45;

// If the server does not receive a heartbeat within this window,
// the session can be treated as stale/expired.
const SESSION_IDLE_TIMEOUT_SECONDS = 2 * 60;

// Maximum total time-reward earnings per user per day.
// ₹100 = 10,000 paise.
const DAILY_REWARD_CAP_PAISE = 10000;
const MIN_WITHDRAWAL_PAISE = 1000;
const MAX_WITHDRAWAL_PAISE = 1000000;

// Server-controlled reward amounts.
// The browser never chooses the reward amount.
const REWARD_AMOUNTS_PAISE = [
  100,   // ₹1
  200,   // ₹2
  300,   // ₹3
  400,   // ₹4
  500,   // ₹5
  1000,  // ₹10
  1500,  // ₹15
];

function deterministicReward(milestoneNumber, userId) {
  const seed = `${String(userId)}:${String(
    milestoneNumber
  )}:sharx-reward-v1`;

  const hash = crypto
    .createHash("sha256")
    .update(seed)
    .digest();

  const value = hash.readUInt32BE(0);

  return REWARD_AMOUNTS_PAISE[
    value % REWARD_AMOUNTS_PAISE.length
  ];
}

module.exports = {
  MILESTONE_SECONDS,
  HEARTBEAT_GRACE_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  DAILY_REWARD_CAP_PAISE,
  MIN_WITHDRAWAL_PAISE,
  MAX_WITHDRAWAL_PAISE,
  deterministicReward,
};
