// Gaming-Backend/routes/rewards.js

const express = require("express");
const crypto = require("crypto");

const authMiddleware = require("../middleware/authMiddleware");
const prisma = require("../lib/prisma");

const {
  startSession,
  heartbeatSession,
  endSession,
  getWallet,
  getHistory,
} = require("../services/rewardService");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| RazorpayX Webhook
|--------------------------------------------------------------------------
| IMPORTANT:
| This route MUST be before router.use(authMiddleware)
| because RazorpayX does not send our user's JWT.
|
| RazorpayX sends:
|   X-Razorpay-Signature
|
| We verify that signature using:
|   RAZORPAYX_WEBHOOK_SECRET
|--------------------------------------------------------------------------
*/

router.post("/webhook/razorpayx", async (req, res) => {
  try {
    const signature =
      req.headers["x-razorpay-signature"];

    const webhookSecret =
      process.env.RAZORPAYX_WEBHOOK_SECRET;

    // Secret must exist
    if (!webhookSecret) {
      console.error(
        "❌ RAZORPAYX_WEBHOOK_SECRET is not configured."
      );

      return res.status(500).json({
        success: false,
        error: "Webhook secret not configured.",
      });
    }

    // Razorpay signature must exist
    if (!signature) {
      console.warn(
        "⚠️ RazorpayX webhook missing signature."
      );

      return res.status(400).json({
        success: false,
        error: "Missing Razorpay signature.",
      });
    }

    // Raw body is required for HMAC verification
    if (!req.rawBody) {
      console.error(
        "❌ RazorpayX webhook raw body is missing."
      );

      return res.status(500).json({
        success: false,
        error: "Raw webhook body unavailable.",
      });
    }

    /*
     * Razorpay webhook signature:
     *
     * HMAC-SHA256(
     *   raw request body,
     *   webhook secret
     * )
     */
    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          webhookSecret
        )
        .update(req.rawBody)
        .digest("hex");

    const receivedBuffer =
      Buffer.from(
        String(signature),
        "utf8"
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "utf8"
      );

    /*
     * timingSafeEqual requires buffers
     * of the same length.
     */
    const signatureValid =
      receivedBuffer.length ===
        expectedBuffer.length &&
      crypto.timingSafeEqual(
        receivedBuffer,
        expectedBuffer
      );

    if (!signatureValid) {
      console.warn(
        "⚠️ Invalid RazorpayX webhook signature."
      );

      return res.status(400).json({
        success: false,
        error: "Invalid webhook signature.",
      });
    }

    /*
     * Signature is valid.
     *
     * At this stage we know the request genuinely came
     * through Razorpay's signed webhook mechanism.
     */
    const event = req.body?.event || "unknown";

    console.log(
      `✅ RazorpayX webhook received: ${event}`
    );

    /*
     * Keep the payload available for the next stage
     * where we will process:
     *
     * payout.initiated
     * payout.queued
     * payout.pending
     * payout.processed
     * payout.updated
     * payout.rejected
     * payout.reversed
     */

    switch (event) {
      case "payout.initiated":
        console.log(
          "💸 RazorpayX payout initiated."
        );
        break;

      case "payout.queued":
        console.log(
          "⏳ RazorpayX payout queued."
        );
        break;

      case "payout.pending":
        console.log(
          "⏳ RazorpayX payout pending."
        );
        break;

      case "payout.processed":
        console.log(
          "✅ RazorpayX payout processed."
        );
        break;

      case "payout.updated":
        console.log(
          "🔄 RazorpayX payout updated."
        );
        break;

      case "payout.rejected":
        console.log(
          "❌ RazorpayX payout rejected."
        );
        break;

      case "payout.reversed":
        console.log(
          "↩️ RazorpayX payout reversed."
        );
        break;

      default:
        console.log(
          `ℹ️ Unhandled RazorpayX event: ${event}`
        );
    }

    /*
     * Always acknowledge a valid webhook.
     * Actual Withdrawal/Wallet state changes will be
     * connected here after the endpoint is verified.
     */
    return res.status(200).json({
      success: true,
      received: true,
      event,
    });
  } catch (error) {
    console.error(
      "❌ RazorpayX webhook error:",
      error
    );

    return res.status(500).json({
      success: false,
      error: "Webhook processing failed.",
    });
  }
});

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
| Everything below this point requires the user's JWT.
|--------------------------------------------------------------------------
*/

router.use(authMiddleware);

function cleanClientInstanceId(value) {
  if (typeof value !== "string") return "";

  return value
    .trim()
    .slice(0, 128);
}

function cleanGameId(value) {
  if (typeof value !== "string") return "";

  return value
    .trim()
    .slice(0, 200);
}

function publicSession(session) {
  return {
    id: session.id,
    gameId: session.gameId,
    status: session.status,
    startedAt: session.startedAt,
    lastHeartbeatAt:
      session.lastHeartbeatAt,
    qualifiedSeconds:
      session.qualifiedSeconds,
    rewardedMilestones:
      session.rewardedMilestones,
  };
}

/*
|--------------------------------------------------------------------------
| GET /rewards/wallet
|--------------------------------------------------------------------------
*/

router.get("/wallet", async (req, res) => {
  try {
    const wallet =
      await getWallet(req.user.id);

    return res.json({
      success: true,
      wallet,
    });
  } catch (error) {
    console.error(
      "GET /rewards/wallet:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Could not load reward wallet.",
    });
  }
});

/*
|--------------------------------------------------------------------------
| GET /rewards/history
|--------------------------------------------------------------------------
*/

router.get("/history", async (req, res) => {
  try {
    const history =
      await getHistory(
        req.user.id,
        req.query.limit
      );

    return res.json({
      success: true,
      history,
    });
  } catch (error) {
    console.error(
      "GET /rewards/history:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Could not load reward history.",
    });
  }
});

/*
|--------------------------------------------------------------------------
| POST /rewards/session/start
|--------------------------------------------------------------------------
*/

router.post(
  "/session/start",
  async (req, res) => {
    try {
      const gameId =
        cleanGameId(
          req.body?.gameId
        );

      const clientInstanceId =
        cleanClientInstanceId(
          req.body?.clientInstanceId
        );

      if (
        !gameId ||
        !clientInstanceId
      ) {
        return res.status(400).json({
          success: false,
          error:
            "gameId and clientInstanceId are required.",
        });
      }

      const session =
        await startSession({
          userId: req.user.id,
          gameId,
          clientInstanceId,
          req,
        });

      return res.status(201).json({
        success: true,
        session:
          publicSession(session),
      });
    } catch (error) {
      if (
        error.code ===
        "ACTIVE_SESSION_EXISTS"
      ) {
        return res.status(409).json({
          success: false,
          code: error.code,
          error: error.message,
        });
      }

      console.error(
        "POST /rewards/session/start:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not start reward session.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| POST /rewards/session/heartbeat
|--------------------------------------------------------------------------
*/

router.post(
  "/session/heartbeat",
  async (req, res) => {
    try {
      const sessionId =
        typeof req.body?.sessionId ===
        "string"
          ? req.body.sessionId.trim()
          : "";

      const clientInstanceId =
        cleanClientInstanceId(
          req.body?.clientInstanceId
        );

      if (
        !sessionId ||
        !clientInstanceId
      ) {
        return res.status(400).json({
          success: false,
          error:
            "sessionId and clientInstanceId are required.",
        });
      }

      const result =
        await heartbeatSession({
          userId: req.user.id,
          sessionId,
          clientInstanceId,
        });

      return res.json({
        success: true,
        ...result,
      });
    } catch (error) {
      if (
        error.code ===
          "SESSION_NOT_ACTIVE" ||
        error.code ===
          "SESSION_CLIENT_MISMATCH"
      ) {
        return res.status(409).json({
          success: false,
          code: error.code,
          error: error.message,
        });
      }

      console.error(
        "POST /rewards/session/heartbeat:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not update reward session.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| POST /rewards/session/end
|--------------------------------------------------------------------------
*/

router.post(
  "/session/end",
  async (req, res) => {
    try {
      const sessionId =
        typeof req.body?.sessionId ===
        "string"
          ? req.body.sessionId.trim()
          : "";

      const clientInstanceId =
        cleanClientInstanceId(
          req.body?.clientInstanceId
        );

      if (
        !sessionId ||
        !clientInstanceId
      ) {
        return res.status(400).json({
          success: false,
          error:
            "sessionId and clientInstanceId are required.",
        });
      }

      const session =
        await endSession({
          userId: req.user.id,
          sessionId,
          clientInstanceId,
        });

      return res.json({
        success: true,
        session: session
          ? publicSession(session)
          : null,
      });
    } catch (error) {
      console.error(
        "POST /rewards/session/end:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not end reward session.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| GET /rewards/me
|--------------------------------------------------------------------------
*/

router.get("/me", async (req, res) => {
  try {
    const [
      wallet,
      history,
      activeSession,
    ] = await Promise.all([
      getWallet(req.user.id),

      getHistory(
        req.user.id,
        20
      ),

      prisma.rewardSession.findFirst({
        where: {
          userId: req.user.id,
          status: "ACTIVE",
        },
        orderBy: {
          startedAt: "desc",
        },
      }),
    ]);

    return res.json({
      success: true,
      wallet,
      history,
      activeSession:
        activeSession
          ? publicSession(
              activeSession
            )
          : null,
    });
  } catch (error) {
    console.error(
      "GET /rewards/me:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Could not load reward information.",
    });
  }
});

module.exports = router;