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
  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }

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

async function startSession({
  userId,
  gameId,
  clientInstanceId,
  req,
}) {
  if (!gameId) {
    throw new Error("Game ID is required.");
  }

  if (!clientInstanceId) {
    throw new Error(
      "Client instance ID is required."
    );
  }

  /*
   * Expire:
   *
   * 1. Same client old active session
   * 2. Any session that has been idle too long
   */

  await prisma.rewardSession.updateMany({
    where: {
      userId,
      status: "ACTIVE",
      OR: [
        {
          clientInstanceId,
        },
        {
          lastHeartbeatAt: {
            lt: new Date(
              Date.now() -
                SESSION_IDLE_TIMEOUT_SECONDS * 1000
            ),
          },
        },
      ],
    },
    data: {
      status: "EXPIRED",
      endedAt: new Date(),
    },
  });

  /*
   * Prevent multiple simultaneously active sessions
   * for the same user.
   */

  const alreadyActive =
    await prisma.rewardSession.findFirst({
      where: {
        userId,
        status: "ACTIVE",
        clientInstanceId: {
          not: clientInstanceId,
        },
      },
    });

  if (alreadyActive) {
    const age =
      Date.now() -
      new Date(
        alreadyActive.lastHeartbeatAt
      ).getTime();

    if (
      age <
      SESSION_IDLE_TIMEOUT_SECONDS * 1000
    ) {
      const error = new Error(
        "Another active play session already exists."
      );

      error.code =
        "ACTIVE_SESSION_EXISTS";

      throw error;
    }

    await prisma.rewardSession.update({
      where: {
        id: alreadyActive.id,
      },
      data: {
        status: "EXPIRED",
        endedAt: new Date(),
      },
    });
  }

  /*
   * Create new server-authoritative session.
   */

  const session =
    await prisma.rewardSession.create({
      data: {
        userId,
        gameId: cleanGameId(gameId),
        clientInstanceId:
          cleanClientInstanceId(
            clientInstanceId
          ),
        ipHash: hashValue(
          getIp(req)
        ),
        userAgentHash:
          hashValue(
            getUserAgent(req)
          ),
      },
    });

  return session;
}

/* =========================================================
   HEARTBEAT
========================================================= */

async function heartbeatSession({
  userId,
  sessionId,
  clientInstanceId,
}) {
  const session =
    await prisma.rewardSession.findFirst({
      where: {
        id: sessionId,
        userId,
        status: "ACTIVE",
      },
    });

  if (!session) {
    const error = new Error(
      "Reward session is no longer active."
    );

    error.code =
      "SESSION_NOT_ACTIVE";

    throw error;
  }

  /*
   * Make sure heartbeat belongs to the same browser
   * instance that started the session.
   */

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

  const now = new Date();

  const last =
    new Date(
      session.lastHeartbeatAt
    );

  let deltaSeconds = Math.floor(
    (
      now.getTime() -
      last.getTime()
    ) / 1000
  );

  /*
   * Never allow negative time.
   */

  if (deltaSeconds < 0) {
    deltaSeconds = 0;
  }

  /*
   * Never credit more than heartbeat grace
   * for one request.
   */

  deltaSeconds = Math.min(
    deltaSeconds,
    HEARTBEAT_GRACE_SECONDS
  );

  const newQualifiedSeconds =
    session.qualifiedSeconds +
    deltaSeconds;

  const oldMilestones =
    session.rewardedMilestones;

  const newMilestones =
    Math.floor(
      newQualifiedSeconds /
        MILESTONE_SECONDS
    );

  const earned = [];

  /*
   * Serializable transaction reduces the possibility
   * of concurrent heartbeat races.
   */

  await prisma.$transaction(
    async (tx) => {
      /*
       * Re-read the session INSIDE the transaction.
       *
       * This is important when two heartbeats arrive
       * almost at the same time.
       */

      const current =
        await tx.rewardSession.findUnique({
          where: {
            id: session.id,
          },
        });

      if (!current) {
        const error = new Error(
          "Reward session no longer exists."
        );

        error.code =
          "SESSION_NOT_ACTIVE";

        throw error;
      }

      if (
        current.userId !== userId ||
        current.status !== "ACTIVE"
      ) {
        const error = new Error(
          "Reward session is no longer active."
        );

        error.code =
          "SESSION_NOT_ACTIVE";

        throw error;
      }

      if (
        current.clientInstanceId !==
        clientInstanceId
      ) {
        const error = new Error(
          "Invalid play session."
        );

        error.code =
          "SESSION_CLIENT_MISMATCH";

        throw error;
      }

      /*
       * Recalculate from the actual current DB state.
       */

      const currentNow = new Date();

      const currentLast =
        new Date(
          current.lastHeartbeatAt
        );

      let currentDeltaSeconds =
        Math.floor(
          (
            currentNow.getTime() -
            currentLast.getTime()
          ) / 1000
        );

      if (currentDeltaSeconds < 0) {
        currentDeltaSeconds = 0;
      }

      currentDeltaSeconds =
        Math.min(
          currentDeltaSeconds,
          HEARTBEAT_GRACE_SECONDS
        );

      const updatedQualifiedSeconds =
        current.qualifiedSeconds +
        currentDeltaSeconds;

      const updatedMilestones =
        Math.floor(
          updatedQualifiedSeconds /
            MILESTONE_SECONDS
        );

      /*
       * Update session.
       */

      const updatedSession =
        await tx.rewardSession.update({
          where: {
            id: current.id,
          },
          data: {
            qualifiedSeconds:
              updatedQualifiedSeconds,

            rewardedMilestones:
              updatedMilestones,

            lastHeartbeatAt:
              currentNow,
          },
        });

      /*
       * Process only newly crossed milestones.
       *
       * creditMilestone() itself only allows #1.
       */

      for (
        let milestone =
          current.rewardedMilestones + 1;

        milestone <=
        updatedMilestones;

        milestone += 1
      ) {
        const ledger =
          await creditMilestone(
            tx,
            updatedSession,
            milestone
          );

        if (ledger) {
          earned.push(ledger);
        }
      }

      /*
       * Return updated values through local variables.
       */

      session.qualifiedSeconds =
        updatedQualifiedSeconds;

      session.rewardedMilestones =
        updatedMilestones;
    },
    {
      isolationLevel:
        "Serializable",
    }
  );

  return {
    sessionId,

    qualifiedSeconds:
      session.qualifiedSeconds,

    rewardedMilestones:
      session.rewardedMilestones,

    earned: earned.map((item) => ({
      id: item.id,

      amountPaise:
        Number(
          item.amountPaise
        ),

      amountRupees:
        Number(
          item.amountPaise
        ) / 100,

      description:
        item.description,
    })),
  };
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