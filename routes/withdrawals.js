const express = require('express');
const rateLimit = require('express-rate-limit');
const authMiddleware = require('../middleware/authMiddleware');
const prisma = require('../lib/prisma');
const { MIN_WITHDRAWAL_PAISE, MAX_WITHDRAWAL_PAISE } = require('../config/rewardConfig');
const { reserveWithdrawal, initiateWithdrawal } = require('../services/withdrawalService');

const router = express.Router();
router.use(authMiddleware);

const withdrawalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many withdrawal attempts. Please try again later.' },
});

function isValidUpiId(value) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{1,127}@[A-Za-z0-9.-]{2,64}$/.test(value);
}

router.post('/', withdrawalLimiter, async (req, res) => {
  try {
    const amountRupees = Number(req.body?.amountRupees);
    const method = typeof req.body?.method === 'string' ? req.body.method.trim().toLowerCase() : '';
    const destination = typeof req.body?.destination === 'string' ? req.body.destination.trim() : '';

    if (!Number.isFinite(amountRupees) || amountRupees <= 0 || !Number.isInteger(amountRupees * 100)) {
      return res.status(400).json({ success: false, error: 'Enter a valid withdrawal amount.' });
    }

    const amountPaise = Math.round(amountRupees * 100);
    if (amountPaise < MIN_WITHDRAWAL_PAISE || amountPaise > MAX_WITHDRAWAL_PAISE) {
      return res.status(400).json({ success: false, error: `Withdrawal must be between ₹${MIN_WITHDRAWAL_PAISE / 100} and ₹${MAX_WITHDRAWAL_PAISE / 100}.` });
    }

    // RazorpayX supports UPI payouts; PayPal is not a RazorpayX payout rail.
    if (method !== 'upi' || !isValidUpiId(destination)) {
      return res.status(400).json({ success: false, error: 'Enter a valid UPI ID for withdrawal.' });
    }

    const withdrawal = await reserveWithdrawal({
      userId: req.user.id,
      amountPaise,
      method,
      destination,
    });

    try {
      const updated = await initiateWithdrawal({ withdrawalId: withdrawal.id });
      return res.status(201).json({
        success: true,
        withdrawal: {
          id: updated.id,
          amountRupees: Number(updated.amountPaise) / 100,
          method: updated.method,
          status: updated.status,
          createdAt: updated.createdAt,
          processedAt: updated.processedAt,
        },
      });
    } catch (providerError) {
      if (providerError.code === 'RAZORPAYX_NOT_CONFIGURED') {
        return res.status(503).json({ success: false, error: 'Withdrawals are temporarily unavailable.' });
      }
      if (providerError.code === 'INVALID_UPI') {
        return res.status(400).json({ success: false, error: 'Invalid UPI ID.' });
      }
      // Ambiguous network/provider errors intentionally return the withdrawal
      // as pending instead of refunding: the provider may already have accepted it.
      return res.status(202).json({
        success: true,
        withdrawal: {
          id: withdrawal.id,
          amountRupees: Number(withdrawal.amountPaise) / 100,
          method: withdrawal.method,
          status: 'PENDING',
          createdAt: withdrawal.createdAt,
        },
        message: 'Withdrawal is being processed. Do not submit it again.',
      });
    }
  } catch (error) {
    if (error.code === 'INSUFFICIENT_BALANCE' || error.code === 'WALLET_NOT_FOUND') {
      return res.status(400).json({ success: false, error: error.message });
    }
    if (error.code === 'P2034') {
      return res.status(409).json({ success: false, error: 'Withdrawal is being processed concurrently. Please try again.' });
    }
    console.error('POST /withdrawals:', error);
    return res.status(500).json({ success: false, error: 'Could not create withdrawal request.' });
  }
});

router.get('/', async (req, res) => {
  try {
    const rows = await prisma.withdrawal.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        id: true,
        amountPaise: true,
        method: true,
        status: true,
        note: true,
        createdAt: true,
        processedAt: true,
        failureReason: true,
        providerPayoutId: true,
      },
    });

    return res.json({
      success: true,
      withdrawals: rows.map((row) => ({
        ...row,
        amountPaise: Number(row.amountPaise),
        amountRupees: Number(row.amountPaise) / 100,
      })),
    });
  } catch (error) {
    console.error('GET /withdrawals:', error);
    return res.status(500).json({ success: false, error: 'Could not load withdrawals.' });
  }
});

module.exports = router;
