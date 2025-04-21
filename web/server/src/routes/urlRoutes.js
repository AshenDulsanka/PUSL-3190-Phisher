import express from 'express'
import { analyzeUrl, reportUrl, getRecentAnalyses } from '../controllers/urlController.js'

const router = express.Router()

// public routes
router.post('/analyze', analyzeUrl)
router.post('/report', reportUrl)
router.get('/recent', getRecentAnalyses)

export default router