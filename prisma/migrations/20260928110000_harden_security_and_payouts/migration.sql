ALTER TABLE "User" ADD COLUMN "tokenVersion" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Withdrawal"
  ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN "providerPayoutId" TEXT,
  ADD COLUMN "providerFundAccountId" TEXT,
  ADD COLUMN "providerReferenceId" TEXT,
  ADD COLUMN "idempotencyKey" TEXT,
  ADD COLUMN "failureReason" TEXT;
CREATE UNIQUE INDEX "Withdrawal_providerPayoutId_key" ON "Withdrawal"("providerPayoutId");
CREATE UNIQUE INDEX "Withdrawal_idempotencyKey_key" ON "Withdrawal"("idempotencyKey");
WITH ranked AS (
  SELECT "id", ROW_NUMBER() OVER (PARTITION BY "userId" ORDER BY "lastHeartbeatAt" DESC, "createdAt" DESC) AS rn
  FROM "RewardSession"
  WHERE "status" = 'ACTIVE'
)
UPDATE "RewardSession"
SET "status" = 'EXPIRED', "endedAt" = CURRENT_TIMESTAMP
WHERE "id" IN (SELECT "id" FROM ranked WHERE rn > 1);
CREATE UNIQUE INDEX "RewardSession_one_active_per_user" ON "RewardSession"("userId") WHERE "status" = 'ACTIVE';
CREATE TABLE "PasswordResetCode" (
  "id" TEXT NOT NULL,
  "userId" INTEGER NOT NULL,
  "codeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PasswordResetCode_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "PasswordResetCode_userId_expiresAt_idx" ON "PasswordResetCode"("userId", "expiresAt");
CREATE INDEX "PasswordResetCode_codeHash_idx" ON "PasswordResetCode"("codeHash");
ALTER TABLE "PasswordResetCode" ADD CONSTRAINT "PasswordResetCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
CREATE TABLE "AuthExchangeCode" (
  "id" TEXT NOT NULL,
  "userId" INTEGER NOT NULL,
  "codeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuthExchangeCode_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AuthExchangeCode_codeHash_key" ON "AuthExchangeCode"("codeHash");
CREATE INDEX "AuthExchangeCode_userId_expiresAt_idx" ON "AuthExchangeCode"("userId", "expiresAt");
ALTER TABLE "AuthExchangeCode" ADD CONSTRAINT "AuthExchangeCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
CREATE TABLE "WebhookEvent" (
  "id" TEXT NOT NULL,
  "provider" TEXT NOT NULL,
  "event" TEXT NOT NULL,
  "payloadHash" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "WebhookEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "WebhookEvent_provider_createdAt_idx" ON "WebhookEvent"("provider", "createdAt");
