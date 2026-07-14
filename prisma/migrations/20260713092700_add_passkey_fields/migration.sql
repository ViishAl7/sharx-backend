/*
  Warnings:

  - A unique constraint covering the columns `[passkeyCredentialId]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "currentChallenge" TEXT,
ADD COLUMN     "currentChallengeExpiresAt" TIMESTAMP(3),
ADD COLUMN     "passkeyCounter" INTEGER,
ADD COLUMN     "passkeyCredentialId" TEXT,
ADD COLUMN     "passkeyPublicKey" BYTEA;

-- CreateIndex
CREATE UNIQUE INDEX "User_passkeyCredentialId_key" ON "public"."User"("passkeyCredentialId");
