/*
  Warnings:

  - You are about to drop the column `redirectedToChatbot` on the `DetectionSession` table. All the data in the column will be lost.
  - You are about to drop the column `userId` on the `url_reports` table. All the data in the column will be lost.
  - You are about to drop the `ChatMessage` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `chat_sessions` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `users` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "ChatMessage" DROP CONSTRAINT "ChatMessage_chatSessionId_fkey";

-- DropForeignKey
ALTER TABLE "chat_sessions" DROP CONSTRAINT "chat_sessions_userId_fkey";

-- DropForeignKey
ALTER TABLE "url_reports" DROP CONSTRAINT "url_reports_userId_fkey";

-- AlterTable
ALTER TABLE "DetectionSession" DROP COLUMN "redirectedToChatbot",
ADD COLUMN     "ipAddress" TEXT;

-- AlterTable
ALTER TABLE "url_reports" DROP COLUMN "userId",
ADD COLUMN     "reporterEmail" TEXT;

-- DropTable
DROP TABLE "ChatMessage";

-- DropTable
DROP TABLE "chat_sessions";

-- DropTable
DROP TABLE "users";

-- CreateTable
CREATE TABLE "admins" (
    "id" SERIAL NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastLoginAt" TIMESTAMP(3),

    CONSTRAINT "admins_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "admins_username_key" ON "admins"("username");

-- CreateIndex
CREATE UNIQUE INDEX "admins_email_key" ON "admins"("email");
