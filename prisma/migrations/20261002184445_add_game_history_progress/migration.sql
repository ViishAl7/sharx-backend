-- CreateTable
CREATE TABLE "GameHistory" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "gameId" TEXT NOT NULL,
    "gameName" TEXT,
    "lastPlayedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "playCount" INTEGER NOT NULL DEFAULT 1,
    "totalPlaySeconds" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GameHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GameProgress" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "gameId" TEXT NOT NULL,
    "progress" JSONB NOT NULL,
    "score" INTEGER,
    "level" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GameProgress_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "GameHistory_userId_lastPlayedAt_idx" ON "GameHistory"("userId", "lastPlayedAt");

-- CreateIndex
CREATE UNIQUE INDEX "GameHistory_userId_gameId_key" ON "GameHistory"("userId", "gameId");

-- CreateIndex
CREATE INDEX "GameProgress_userId_updatedAt_idx" ON "GameProgress"("userId", "updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "GameProgress_userId_gameId_key" ON "GameProgress"("userId", "gameId");

-- CreateIndex
CREATE INDEX "Match_userId_createdAt_idx" ON "Match"("userId", "createdAt");

-- AddForeignKey
ALTER TABLE "GameHistory" ADD CONSTRAINT "GameHistory_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GameProgress" ADD CONSTRAINT "GameProgress_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
