// Gaming-Backend/services/rewardService.js
//
// Server-authoritative reward engine.
// ONE-TIME FIRST-HOUR REWARD:
// A user can receive the 60-minute time reward only once
// during their entire lifetime on SHARX.

const crypto = require("crypto");
const prisma = require("../lib/prisma");

const {
  MILESTONE_SECONDS,
  HEARTBEAT_GRACE_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  DAILY_REWARD_CAP_PAISE,
  deterministicReward,
} = require("../config/rewardConfig");

/* =========================================================
   HELPERS
========================================================= */

function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function cleanGameId(value) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, 200);
}

function cleanClientInstanceId(value) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, 128);
}

function getIp(req) {
  // Express resolves the client IP according to the configured trust proxy.
  // Do not parse X-Forwarded-For manually because an untrusted caller can
  // otherwise inject arbitrary values into the fingerprint.
  return req.ip || req.socket?.remoteAddress || "";
}

function getUserAgent(req) {
  return req.get("user-agent") || "";
}

/* =========================================================
   WALLET
========================================================= */

async function ensureWallet(tx, userId) {
  return tx.rewardWallet.upsert({
    where: {
      userId,
    },
    create: {
      userId,
      balancePaise: 0,
      lifetimeEarnedPaise: 0,
      lifetimeWithdrawnPaise: 0,
    },
    update: {},
  });
}

/* =========================================================
   DAILY CAP
========================================================= */

async function getDailyRewardTotal(tx, userId) {
  const start = new Date();

  start.setHours(0, 0, 0, 0);

  const result = await tx.rewardLedger.aggregate({
    where: {
      userId,
      type: "TIME_REWARD",
      amountPaise: {
        gt: 0,
      },
      createdAt: {
        gte: start,
      },
    },
    _sum: {
      amountPaise: true,
    },
  });

  return Number(result._sum.amountPaise || 0);
}

/* =========================================================
   CHECK WHETHER USER ALREADY CLAIMED
========================================================= */

async function hasClaimedFirstHourReward(tx, userId) {
  const referenceKey = `time:first-hour:${userId}`;

  const existing = await tx.rewardLedger.findUnique({
    where: {
      referenceKey,
    },
    select: {
      id: true,
    },
  });

  return Boolean(existing);
}

/* =========================================================
   CREDIT FIRST-HOUR REWARD
========================================================= */

async function creditMilestone(
  tx,
  session,
  milestoneNumber
) {
  /*
   * IMPORTANT:
   *
   * Only milestone #1 is eligible.
   *
   * Therefore:
   *
   * 1 hour  -> possible reward
   * 2 hours -> no reward
   * 3 hours -> no reward
   * etc.
   */

  if (milestoneNumber !== 1) {
    return null;
  }

  /*
   * One permanent reference for this user's lifetime
   * first-hour reward.
   *
   * It is NOT based on session.id.
   *
   * This is what prevents:
   *
   * session A -> reward
   * session B -> reward
   * session C -> reward
   */

  const referenceKey =
    `time:first-hour:${session.userId}`;

  /*
   * Check whether reward already exists.
   */

  const existing = await tx.rewardLedger.findUnique({
    where: {
      referenceKey,
    },
  });

  if (existing) {
    return null;
  }

  /*
   * Server-controlled deterministic reward.
   *
   * Always uses milestone 1.
   * Browser cannot choose the amount.
   */

  const rewardPaise = deterministicReward(
    1,
    session.userId
  );

  /*
   * Daily cap protection.
   */

  const dailyTotal = await getDailyRewardTotal(
    tx,
    session.userId
  );

  if (
    dailyTotal + rewardPaise >
    DAILY_REWARD_CAP_PAISE
  ) {
    return null;
  }

  /*
   * Get/create wallet.
   */

  const wallet = await ensureWallet(
    tx,
    session.userId
  );

  const newBalance =
    BigInt(wallet.balancePaise) +
    BigInt(rewardPaise);

  const newLifetime =
    BigInt(wallet.lifetimeEarnedPaise) +
    BigInt(rewardPaise);

  /*
   * Create immutable reward ledger entry.
   *
   * referenceKey is UNIQUE in Prisma.
   */

  let ledger;

  try {
    ledger = await tx.rewardLedger.create({
      data: {
        walletId: wallet.id,
        userId: session.userId,
        type: "TIME_REWARD",
        amountPaise: rewardPaise,
        balanceAfterPaise: newBalance,
        referenceKey,
        description:
          "SHARX one-time 60-minute play reward",
        metadata: {
          rewardType: "ONE_TIME_FIRST_HOUR",
          sessionId: session.id,
          gameId: session.gameId,
          milestoneSeconds:
            MILESTONE_SECONDS,
        },
      },
    });
  } catch (error) {
    /*
     * P2002 = unique constraint violation.
     *
     * This can happen if two heartbeat requests arrive
     * almost simultaneously.
     *
     * The database wins:
     * only ONE request can create the reward.
     */

    if (error?.code === "P2002") {
      const alreadyCreated =
        await tx.rewardLedger.findUnique({
          where: {
            referenceKey,
          },
        });

      if (alreadyCreated) {
        return null;
      }
    }

    throw error;
  }

  /*
   * Create milestone record.
   */

  try {
    await tx.rewardMilestone.create({
      data: {
        userId: session.userId,
        sessionId: session.id,
        milestoneSeconds:
          MILESTONE_SECONDS,
        rewardPaise,
        referenceKey,
      },
    });
  } catch (error) {
    /*
     * If the milestone already exists because of a race,
     * do not create another one.
     */

    if (error?.code !== "P2002") {
      throw error;
    }
  }

  /*
   * Update wallet ONLY after the ledger was successfully
   * created by this transaction.
   */

  await tx.rewardWallet.update({
    where: {
      id: wallet.id,
    },
    data: {
      balancePaise: newBalance,
      lifetimeEarnedPaise: newLifetime,
    },
  });

  return ledger;
}

/* =========================================================
   START SESSION
========================================================= */

async function startSession({ userId, gameId, clientInstanceId, req }) {
  if (!gameId) throw new Error('Game ID is required.');
  if (!clientInstanceId) throw new Error('Client instance ID is required.');

  const cleanClient = cleanClientInstanceId(clientInstanceId);
  const cleanGame = cleanGameId(gameId);
  const now = new Date();
  const staleBefore = new Date(now.getTime() - SESSION_IDLE_TIMEOUT_SECONDS * 1000);

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await prisma.$transaction(async (tx) => {
        await tx.rewardSession.updateMany({
          where: {
            userId,
            status: 'ACTIVE',
            OR: [
              { clientInstanceId: cleanClient },
              { lastHeartbeatAt: { lt: staleBefore } },
            ],
          },
          data: { status: 'EXPIRED', endedAt: now },
        });

        const active = await tx.rewardSession.findFirst({
          where: { userId, status: 'ACTIVE' },
          select: { id: true, clientInstanceId: true, lastHeartbeatAt: true },
        });

        if (active) {
          const error = new Error('Another active play session already exists.');
          error.code = 'ACTIVE_SESSION_EXISTS';
          throw error;
        }

        return tx.rewardSession.create({
          data: {
            userId,
            gameId: cleanGame,
            clientInstanceId: cleanClient,
            ipHash: hashValue(getIp(req)),
            userAgentHash: hashValue(getUserAgent(req)),
          },
        });
      }, { isolationLevel: 'Serializable' });
    } catch (error) {
      if (error.code === 'P2034' && attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 25 * (attempt + 1)));
        continue;
      }
      if (error.code === 'P2002') {
        error.code = 'ACTIVE_SESSION_EXISTS';
      }
      throw error;
    }
  }
  throw new Error('Could not start reward session.');
}

/* =========================================================
   HEARTBEAT
========================================================= */

async function heartbeatSession({ userId, sessionId, clientInstanceId }) {
  const cleanClient = cleanClientInstanceId(clientInstanceId);
  if (!sessionId || !cleanClient) {
    const error = new Error('Invalid reward heartbeat.');
    error.code = 'SESSION_INVALID';
    throw error;
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const earned = [];
    try {
      let response;
      await prisma.$transaction(async (tx) => {
        const current = await tx.rewardSession.findUnique({ where: { id: sessionId } });
        if (!current || current.userId !== userId || current.status !== 'ACTIVE') {
          const error = new Error('Reward session is no longer active.');
          error.code = 'SESSION_NOT_ACTIVE';
          throw error;
        }
        if (current.clientInstanceId !== cleanClient) {
          const error = new Error('Invalid play session.');
          error.code = 'SESSION_CLIENT_MISMATCH';
          throw error;
        }

        const now = new Date();
        const last = new Date(current.lastHeartbeatAt);
        let delta = Math.floor((now.getTime() - last.getTime()) / 1000);
        delta = Math.max(0, Math.min(delta, HEARTBEAT_GRACE_SECONDS));

        const qualifiedSeconds = current.qualifiedSeconds + delta;
        const milestones = Math.floor(qualifiedSeconds / MILESTONE_SECONDS);
        const updated = await tx.rewardSession.update({
          where: { id: current.id },
          data: { qualifiedSeconds, rewardedMilestones: milestones, lastHeartbeatAt: now },
        });

        for (let milestone = current.rewardedMilestones + 1; milestone <= milestones; milestone += 1) {
          const ledger = await creditMilestone(tx, updated, milestone);
          if (ledger) earned.push(ledger);
        }

        response = { sessionId, qualifiedSeconds, rewardedMilestones: milestones };
      }, { isolationLevel: 'Serializable' });

      return { ...response, earned: earned.map((item) => ({
        id: item.id,
        amountPaise: Number(item.amountPaise),
        amountRupees: Number(item.amountPaise) / 100,
        description: item.description,
      })) };
    } catch (error) {
      if (error.code === 'P2034' && attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 25 * (attempt + 1)));
        continue;
      }
      throw error;
    }
  }
  throw new Error('Could not update reward session.');
}

/* =========================================================
   END SESSION
========================================================= */

async function endSession({
  userId,
  sessionId,
  clientInstanceId,
}) {
  const session =
    await prisma.rewardSession.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

  // Session already completed/expired/revoked.
  // Nothing else needs to be done.
  if (!session) {
    return null;
  }

  // If the session is no longer active, treat the request
  // as an idempotent cleanup request.
  if (session.status !== "ACTIVE") {
    return session;
  }

  // Only the same client that started the session
  // can end it.
  if (
    session.clientInstanceId !==
    clientInstanceId
  ) {
    const error = new Error(
      "Invalid play session."
    );

    error.code =
      "SESSION_CLIENT_MISMATCH";

    throw error;
  }

  return prisma.rewardSession.update({
    where: {
      id: session.id,
    },
    data: {
      status: "COMPLETED",
      endedAt: new Date(),
    },
  });
}
/* =========================================================
   WALLET
========================================================= */

async function getWallet(userId) {
  const wallet =
    await prisma.rewardWallet.upsert({
      where: {
        userId,
      },

      create: {
        userId,
      },

      update: {},
    });

  return {
    balancePaise:
      Number(
        wallet.balancePaise
      ),

    balanceRupees:
      Number(
        wallet.balancePaise
      ) / 100,

    lifetimeEarnedPaise:
      Number(
        wallet.lifetimeEarnedPaise
      ),

    lifetimeEarnedRupees:
      Number(
        wallet.lifetimeEarnedPaise
      ) / 100,

    lifetimeWithdrawnPaise:
      Number(
        wallet.lifetimeWithdrawnPaise
      ),

    lifetimeWithdrawnRupees:
      Number(
        wallet.lifetimeWithdrawnPaise
      ) / 100,
  };
}

/* =========================================================
   HISTORY
========================================================= */

async function getHistory(
  userId,
  limit = 50
) {
  const rows =
    await prisma.rewardLedger.findMany({
      where: {
        userId,
      },

      orderBy: {
        createdAt: "desc",
      },

      take: Math.min(
        Math.max(
          Number(limit) || 50,
          1
        ),
        100
      ),

      select: {
        id: true,
        type: true,
        amountPaise: true,
        description: true,
        createdAt: true,
        metadata: true,
      },
    });

  return rows.map((row) => ({
    ...row,

    amountPaise:
      Number(
        row.amountPaise
      ),

    amountRupees:
      Number(
        row.amountPaise
      ) / 100,
  }));
}

/* =========================================================
   EXPORTS
========================================================= */

module.exports = {
  startSession,
  heartbeatSession,
  endSession,
  getWallet,
  getHistory,
};