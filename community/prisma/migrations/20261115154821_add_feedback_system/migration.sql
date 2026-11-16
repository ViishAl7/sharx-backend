-- CreateTable
CREATE TABLE "Feedback" (
    "id" UUID NOT NULL,
    "userId" UUID,
    "overallRating" INTEGER NOT NULL,
    "designRating" INTEGER,
    "gamesRating" INTEGER,
    "speedRating" INTEGER,
    "experienceRating" INTEGER,
    "recommendation" VARCHAR(20) NOT NULL,
    "message" VARCHAR(1500),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Feedback_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Feedback_createdAt_idx" ON "Feedback"("createdAt");

-- CreateIndex
CREATE INDEX "Feedback_userId_createdAt_idx" ON "Feedback"("userId", "createdAt");

-- AddForeignKey
ALTER TABLE "Feedback" ADD CONSTRAINT "Feedback_userId_fkey" FOREIGN KEY ("userId") REFERENCES "CommunityUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;
