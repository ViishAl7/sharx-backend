const crypto = require('crypto');

const RAZORPAY_API_BASE = 'https://api.razorpay.com/v1';

function requireConfig() {
  if (process.env.RAZORPAYX_ENABLED !== 'true') {
    const error = new Error('RazorpayX payouts are disabled.');
    error.code = 'RAZORPAYX_NOT_CONFIGURED';
    throw error;
  }
  const required = [
    'RAZORPAYX_KEY_ID',
    'RAZORPAYX_KEY_SECRET',
    'RAZORPAYX_ACCOUNT_NUMBER',
  ];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) {
    const error = new Error(`RazorpayX payout configuration is incomplete: ${missing.join(', ')}`);
    error.code = 'RAZORPAYX_NOT_CONFIGURED';
    throw error;
  }
}

function basicAuthHeader() {
  return `Basic ${Buffer.from(`${process.env.RAZORPAYX_KEY_ID}:${process.env.RAZORPAYX_KEY_SECRET}`).toString('base64')}`;
}

async function razorpayRequest(path, { method = 'GET', body, idempotencyKey } = {}) {
  requireConfig();

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  try {
    const response = await fetch(`${RAZORPAY_API_BASE}${path}`, {
      method,
      headers: {
        Authorization: basicAuthHeader(),
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(idempotencyKey ? { 'X-Payout-Idempotency': idempotencyKey } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = null; }

    if (!response.ok) {
      const description = data?.error?.description || data?.error?.code || `HTTP ${response.status}`;
      const error = new Error(description);
      error.code = data?.error?.code || 'RAZORPAYX_API_ERROR';
      error.statusCode = response.status;
      error.providerResponse = data;
      throw error;
    }

    return data;
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeoutError = new Error('RazorpayX request timed out. The payout remains pending and can be safely retried with the same idempotency key.');
      timeoutError.code = 'RAZORPAYX_TIMEOUT';
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function sanitizeName(name) {
  return String(name || 'SHARX User').replace(/[^a-zA-Z0-9 ._-]/g, '').trim().slice(0, 100) || 'SHARX User';
}

function buildPayoutReference(withdrawalId) {
  return `sharx_${withdrawalId}`.slice(0, 40);
}

async function createUpiPayout({ withdrawalId, user, amountPaise, upiId }) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}@[A-Za-z0-9.-]{2,64}$/.test(upiId)) {
    const error = new Error('Invalid UPI ID.');
    error.code = 'INVALID_UPI';
    throw error;
  }

  const idempotencyKey = crypto
    .createHash('sha256')
    .update(`sharx:payout:${withdrawalId}`)
    .digest('hex');

  const payload = {
    account_number: process.env.RAZORPAYX_ACCOUNT_NUMBER,
    amount: amountPaise,
    currency: 'INR',
    mode: 'UPI',
    purpose: 'payout',
    queue_if_low_balance: false,
    reference_id: buildPayoutReference(withdrawalId),
    narration: 'SHARX Reward',
    notes: {
      withdrawal_id: withdrawalId,
      user_id: String(user.id),
    },
    fund_account: {
      account_type: 'vpa',
      vpa: {
        address: upiId,
      },
      contact: {
        name: sanitizeName(user.name),
        email: user.email,
        type: 'customer',
        reference_id: `sharx_user_${user.id}`.slice(0, 40),
      },
    },
  };

  const response = await razorpayRequest('/payouts', {
    method: 'POST',
    body: payload,
    idempotencyKey,
  });

  return {
    payoutId: response?.id || null,
    fundAccountId: response?.fund_account_id || response?.fund_account?.id || null,
    status: response?.status || 'queued',
    referenceId: response?.reference_id || payload.reference_id,
    idempotencyKey,
    raw: response,
  };
}

module.exports = {
  createUpiPayout,
};
