const crypto = require('crypto');
const prisma = require('../lib/prisma');
const { createUpiPayout } = require('./razorpayxService');

function payoutReference(withdrawalId) {
  return `sharx_${withdrawalId}`.slice(0, 40);
}

async function reserveWithdrawal({ userId, amountPaise, method, destination }) {
  return prisma.$transaction(async (tx) => {
    const wallet = await tx.rewardWallet.findUnique({ where: { userId } });
    if (!wallet) {
      const error = new Error('Reward wallet not found.');
      error.code = 'WALLET_NOT_FOUND';
      throw error;
    }

    const updated = await tx.rewardWallet.updateMany({
      where: { id: wallet.id, balancePaise: { gte: BigInt(amountPaise) } },
      data: { balancePaise: { decrement: BigInt(amountPaise) } },
    });

    if (updated.count !== 1) {
      const error = new Error('Insufficient reward balance.');
      error.code = 'INSUFFICIENT_BALANCE';
      throw error;
    }

    const withdrawal = await tx.withdrawal.create({
      data: {
        walletId: wallet.id,
        userId,
        amountPaise: BigInt(amountPaise),
        method,
        destination,
        status: 'PENDING',
      },
    });

    const walletAfter = await tx.rewardWallet.findUnique({ where: { id: wallet.id } });

    await tx.rewardLedger.create({
      data: {
        walletId: wallet.id,
        userId,
        type: 'WITHDRAWAL',
        amountPaise: -BigInt(amountPaise),
        balanceAfterPaise: walletAfter.balancePaise,
        referenceKey: `withdrawal:${withdrawal.id}`,
        description: `Withdrawal reservation via ${method}`,
        metadata: { withdrawalId: withdrawal.id, method },
      },
    });

    return withdrawal;
  }, { isolationLevel: 'Serializable' });
}

async function refundWithdrawalTx(tx, withdrawal, reason) {
  const referenceKey = `withdrawal-reversal:${withdrawal.id}`;
  const existing = await tx.rewardLedger.findUnique({ where: { referenceKey } });
  if (existing) return false;

  const wallet = await tx.rewardWallet.findUnique({ where: { id: withdrawal.walletId } });
  if (!wallet) throw new Error('Reward wallet not found while refunding withdrawal.');

  const newBalance = BigInt(wallet.balancePaise) + BigInt(withdrawal.amountPaise);
  await tx.rewardWallet.update({
    where: { id: wallet.id },
    data: {
      balancePaise: newBalance,
      ...(withdrawal.status === 'PAID'
        ? { lifetimeWithdrawnPaise: { decrement: BigInt(withdrawal.amountPaise) } }
        : {}),
    },
  });

  await tx.rewardLedger.create({
    data: {
      walletId: wallet.id,
      userId: withdrawal.userId,
      type: 'WITHDRAWAL_REVERSAL',
      amountPaise: BigInt(withdrawal.amountPaise),
      balanceAfterPaise: newBalance,
      referenceKey,
      description: 'Withdrawal refunded after payout failure/reversal',
      metadata: { withdrawalId: withdrawal.id, reason: String(reason || 'unknown').slice(0, 500) },
    },
  });

  await tx.withdrawal.update({
    where: { id: withdrawal.id },
    data: {
      status: 'REJECTED',
      failureReason: String(reason || 'Payout rejected').slice(0, 1000),
      processedAt: new Date(),
    },
  });

  return true;
}

async function markProviderResult(withdrawalId, payout) {
  return prisma.$transaction(async (tx) => {
    const withdrawal = await tx.withdrawal.findUnique({ where: { id: withdrawalId } });
    if (!withdrawal) throw new Error('Withdrawal not found.');

    const status = String(payout.status || '').toLowerCase();
    if (status === 'processed') {
      if (withdrawal.status === 'PAID' || withdrawal.status === 'REJECTED') return withdrawal;
      const updated = await tx.withdrawal.update({
        where: { id: withdrawal.id },
        data: {
          status: 'PAID',
          providerPayoutId: payout.payoutId || withdrawal.providerPayoutId,
          providerFundAccountId: payout.fundAccountId || withdrawal.providerFundAccountId,
          providerReferenceId: payout.referenceId || withdrawal.providerReferenceId,
          idempotencyKey: payout.idempotencyKey || withdrawal.idempotencyKey,
          processedAt: new Date(),
          failureReason: null,
        },
      });
      await tx.rewardWallet.update({
        where: { id: withdrawal.walletId },
        data: { lifetimeWithdrawnPaise: { increment: BigInt(withdrawal.amountPaise) } },
      });
      return updated;
    }

    if (['rejected', 'failed', 'cancelled', 'reversed'].includes(status)) {
      const withProvider = await tx.withdrawal.update({
        where: { id: withdrawal.id },
        data: {
          providerPayoutId: payout.payoutId || withdrawal.providerPayoutId,
          providerFundAccountId: payout.fundAccountId || withdrawal.providerFundAccountId,
          providerReferenceId: payout.referenceId || withdrawal.providerReferenceId,
          idempotencyKey: payout.idempotencyKey || withdrawal.idempotencyKey,
          failureReason: payout.failureReason || `RazorpayX payout ${status}`,
        },
      });
      if (withdrawal.status !== 'REJECTED') await refundWithdrawalTx(tx, withProvider, withProvider.failureReason);
      return tx.withdrawal.findUnique({ where: { id: withdrawal.id } });
    }

    return tx.withdrawal.update({
      where: { id: withdrawal.id },
      data: {
        status: 'PROCESSING',
        providerPayoutId: payout.payoutId || withdrawal.providerPayoutId,
        providerFundAccountId: payout.fundAccountId || withdrawal.providerFundAccountId,
        providerReferenceId: payout.referenceId || withdrawal.providerReferenceId,
        idempotencyKey: payout.idempotencyKey || withdrawal.idempotencyKey,
      },
    });
  }, { isolationLevel: 'Serializable' });
}

async function initiateWithdrawal({ withdrawalId }) {
  const withdrawal = await prisma.withdrawal.findUnique({
    where: { id: withdrawalId },
    include: { user: { select: { id: true, name: true, email: true } } },
  });
  if (!withdrawal) throw new Error('Withdrawal not found.');
  if (withdrawal.status !== 'PENDING' && withdrawal.status !== 'PROCESSING') return withdrawal;

  try {
    const payout = await createUpiPayout({
      withdrawalId,
      user: withdrawal.user,
      amountPaise: Number(withdrawal.amountPaise),
      upiId: withdrawal.destination,
    });
    return markProviderResult(withdrawalId, payout);
  } catch (error) {
    // An explicit provider rejection is safe to refund immediately. A timeout
    // is ambiguous: Razorpay may have received the request, so leave it pending
    // and allow a retry with the same idempotency key instead of double-paying.
    if (error.code === 'RAZORPAYX_NOT_CONFIGURED' || error.code === 'INVALID_UPI' || (error.statusCode >= 400 && error.statusCode < 500 && error.statusCode !== 408 && error.statusCode !== 429)) {
      await prisma.$transaction(async (tx) => {
        const row = await tx.withdrawal.findUnique({ where: { id: withdrawalId } });
        if (row && row.status !== 'REJECTED' && row.status !== 'PAID') {
          await refundWithdrawalTx(tx, row, error.message);
        }
      }, { isolationLevel: 'Serializable' });
      throw error;
    }
    throw error;
  }
}

async function processRazorpayWebhook({ eventId, event, payload, rawBodyHash }) {
  const payout = payload?.payload?.payout?.entity;
  if (!payout?.id) return { ignored: true, reason: 'No payout entity' };

  return prisma.$transaction(async (tx) => {
    try {
      await tx.webhookEvent.create({
        data: {
          id: eventId,
          provider: 'razorpayx',
          event,
          payloadHash: rawBodyHash,
        },
      });
    } catch (error) {
      if (error?.code === 'P2002') return { duplicate: true };
      throw error;
    }

    const payoutMatch = [{ providerPayoutId: payout.id }];
    if (payout.reference_id) payoutMatch.push({ providerReferenceId: payout.reference_id });
    const withdrawal = await tx.withdrawal.findFirst({ where: { OR: payoutMatch } });

    if (!withdrawal) return { ignored: true, reason: 'Unknown payout' };
    if (withdrawal.status === 'PAID' && event !== 'payout.reversed') return { ignored: true, reason: 'Already paid' };
    if (withdrawal.status === 'REJECTED' && event !== 'payout.processed') return { ignored: true, reason: 'Already rejected' };

    const providerStatus = String(payout.status || '').toLowerCase();
    if (event === 'payout.processed' || providerStatus === 'processed') {
      if (withdrawal.status !== 'PAID') {
        await tx.withdrawal.update({
          where: { id: withdrawal.id },
          data: {
            status: 'PAID',
            providerPayoutId: payout.id,
            providerFundAccountId: payout.fund_account_id || withdrawal.providerFundAccountId,
            providerReferenceId: payout.reference_id || withdrawal.providerReferenceId,
            processedAt: new Date(),
            failureReason: null,
          },
        });
        await tx.rewardWallet.update({
          where: { id: withdrawal.walletId },
          data: { lifetimeWithdrawnPaise: { increment: BigInt(withdrawal.amountPaise) } },
        });
      }
      return { processed: true };
    }

    if (event === 'payout.reversed' || event === 'payout.rejected' || event === 'payout.failed' || ['reversed', 'rejected', 'failed', 'cancelled'].includes(providerStatus)) {
      await refundWithdrawalTx(tx, {
        ...withdrawal,
        providerPayoutId: payout.id,
        failureReason: payout.failure_reason || payout?.error?.description || `RazorpayX payout ${providerStatus}`,
      }, payout.failure_reason || payout?.error?.description || `RazorpayX payout ${providerStatus}`);
      return { refunded: true };
    }

    await tx.withdrawal.update({
      where: { id: withdrawal.id },
      data: {
        status: 'PROCESSING',
        providerPayoutId: payout.id,
        providerFundAccountId: payout.fund_account_id || withdrawal.providerFundAccountId,
        providerReferenceId: payout.reference_id || withdrawal.providerReferenceId,
      },
    });
    return { updated: true };
  }, { isolationLevel: 'Serializable' });
}

module.exports = { reserveWithdrawal, initiateWithdrawal, processRazorpayWebhook };
