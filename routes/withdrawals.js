// Gaming-Backend/routes/withdrawals.js
//
// This creates a secure withdrawal request and reserves the money.
// It does NOT pretend to send money to a bank/UPI/PayPal account.
// Actual payout requires a real payout provider or an admin payout process.

const express = require("express");

const authMiddleware = require("../middleware/authMiddleware");
const prisma = require("../lib/prisma");
const {
  MIN_WITHDRAWAL_PAISE,
} = require("../config/rewardConfig");

const router = express.Router();

router.use(authMiddleware);

router.post("/", async (req, res) => {
  try {
    const amountRupees = Number(
      req.body?.amountRupees
    );

    const method =
      typeof req.body?.method === "string"
        ? req.body.method.trim().toLowerCase()
        : "";

    const destination =
      typeof req.body?.destination === "string"
        ? req.body.destination.trim()
        : "";

    if (
      !Number.isFinite(amountRupees) ||
      amountRupees <= 0
    ) {
      return res.status(400).json({
        success: false,
        error:
          "Enter a valid withdrawal amount.",
      });
    }

    if (!Number.isInteger(amountRupees * 100)) {
      return res.status(400).json({
        success: false,
        error:
          "Amount must be valid to paise precision.",
      });
    }

    const amountPaise = Math.round(
      amountRupees * 100
    );

    if (
      amountPaise <
      MIN_WITHDRAWAL_PAISE
    ) {
      return res.status(400).json({
        success: false,
        error:
          "Minimum withdrawal amount is ₹10.",
      });
    }

    if (
      !["upi", "paypal"].includes(method)
    ) {
      return res.status(400).json({
        success: false,
        error:
          "Supported withdrawal methods are UPI and PayPal.",
      });
    }

    if (
      !destination ||
      destination.length > 254
    ) {
      return res.status(400).json({
        success: false,
        error:
          "A valid payout destination is required.",
      });
    }

    const withdrawal =
      await prisma.$transaction(
        async (tx) => {
          const wallet =
            await tx.rewardWallet.findUnique({
              where: {
                userId: req.user.id,
              },
            });

          if (!wallet) {
            throw Object.assign(
              new Error(
                "Reward wallet not found."
              ),
              {
                code: "WALLET_NOT_FOUND",
              }
            );
          }

          const balance = BigInt(
            wallet.balancePaise
          );

          if (
            balance <
            BigInt(amountPaise)
          ) {
            throw Object.assign(
              new Error(
                "Insufficient reward balance."
              ),
              {
                code:
                  "INSUFFICIENT_BALANCE",
              }
            );
          }

          const updatedWallet =
            await tx.rewardWallet.update({
              where: {
                id: wallet.id,
              },
              data: {
                balancePaise: {
                  decrement:
                    BigInt(amountPaise),
                },
                lifetimeWithdrawnPaise: {
                  increment:
                    BigInt(amountPaise),
                },
              },
            });

          const created =
            await tx.withdrawal.create({
              data: {
                walletId: wallet.id,
                userId: req.user.id,
                amountPaise:
                  BigInt(amountPaise),
                method,
                destination,
                status: "PENDING",
              },
            });

          await tx.rewardLedger.create({
            data: {
              walletId: wallet.id,
              userId: req.user.id,
              type: "WITHDRAWAL",
              amountPaise:
                -amountPaise,
              balanceAfterPaise:
                updatedWallet.balancePaise,
              referenceKey:
                `withdrawal:${created.id}`,
              description:
                `Withdrawal request via ${method}`,
              metadata: {
                withdrawalId:
                  created.id,
                method,
              },
            },
          });

          return created;
        }
      );

    return res.status(201).json({
      success: true,
      withdrawal: {
        id: withdrawal.id,
        amountRupees:
          Number(
            withdrawal.amountPaise
          ) / 100,
        method: withdrawal.method,
        status: withdrawal.status,
        createdAt:
          withdrawal.createdAt,
      },
    });
  } catch (error) {
    if (
      error.code ===
        "INSUFFICIENT_BALANCE" ||
      error.code ===
        "WALLET_NOT_FOUND"
    ) {
      return res.status(400).json({
        success: false,
        error: error.message,
      });
    }

    console.error(
      "POST /withdrawals:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Could not create withdrawal request.",
    });
  }
});

router.get("/", async (req, res) => {
  try {
    const rows =
      await prisma.withdrawal.findMany({
        where: {
          userId: req.user.id,
        },
        orderBy: {
          createdAt: "desc",
        },
        take: 50,
        select: {
          id: true,
          amountPaise: true,
          method: true,
          status: true,
          note: true,
          createdAt: true,
          processedAt: true,
        },
      });

    return res.json({
      success: true,
      withdrawals: rows.map((row) => ({
        ...row,
        amountPaise:
          Number(row.amountPaise),
        amountRupees:
          Number(row.amountPaise) / 100,
      })),
    });
  } catch (error) {
    console.error(
      "GET /withdrawals:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Could not load withdrawals.",
    });
  }
});

module.exports = router;