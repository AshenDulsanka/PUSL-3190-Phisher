import express from 'express'
import { analyzeUrl, reportUrl, getRecentAnalyses } from '../controllers/urlController.js'
import { saveURLAnalysis, processFeedbackBatch, logSystemEvent, getModelMetrics, registerModel, trackModelEvaluation } from '../controllers/internalController.js'

const router = express.Router()

// public routes
router.post('/analyze', analyzeUrl)
router.post('/report', reportUrl)
router.get('/recent', getRecentAnalyses)

router.post('/save-analysis', saveURLAnalysis)
router.post('/process-feedback-batch', processFeedbackBatch)
router.post('/log/system', logSystemEvent)
router.get('/model-metrics/:modelName', getModelMetrics)
router.post('/model/register', registerModel)
router.post('/model/evaluation', trackModelEvaluation)

export default router