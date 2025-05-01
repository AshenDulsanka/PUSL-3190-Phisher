/*
  Warnings:

  - You are about to drop the `url_reports` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "url_reports" DROP CONSTRAINT "url_reports_urlId_fkey";

-- AlterTable
ALTER TABLE "MLModel" ADD COLUMN     "feedbackIncorporated" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lastUpdated" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "URL" ADD COLUMN     "analysisSources" TEXT[],
ADD COLUMN     "analyzeCount" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "detectedPhishingCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lastAnalyzed" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- DropTable
DROP TABLE "url_reports";

-- CreateTable
CREATE TABLE "URLReport" (
    "id" SERIAL NOT NULL,
    "reportedUrl" TEXT NOT NULL,
    "reportType" TEXT NOT NULL,
    "comments" TEXT,
    "reportedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reporterEmail" TEXT,
    "source" TEXT,
    "urlId" INTEGER,

    CONSTRAINT "URLReport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ModelTrainingLog" (
    "id" SERIAL NOT NULL,
    "logType" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "metrics" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modelId" INTEGER NOT NULL,

    CONSTRAINT "ModelTrainingLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FeedbackQueue" (
    "id" SERIAL NOT NULL,
    "url" TEXT NOT NULL,
    "isPhishing" BOOLEAN NOT NULL,
    "feedbackType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processed" BOOLEAN NOT NULL DEFAULT false,
    "processedAt" TIMESTAMP(3),

    CONSTRAINT "FeedbackQueue_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "URLReport" ADD CONSTRAINT "URLReport_urlId_fkey" FOREIGN KEY ("urlId") REFERENCES "URL"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ModelTrainingLog" ADD CONSTRAINT "ModelTrainingLog_modelId_fkey" FOREIGN KEY ("modelId") REFERENCES "MLModel"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
