import express from 'express'
import { login, getStats, getRecentPhishing, getLogs, getModels, getModelEvaluations } from '../controllers/adminController.js'
import { requireAdmin } from '../middleware/auth.js'

const router = express.Router()

// public routes
router.post('/login', login)

// protected routes
router.get('/stats', requireAdmin, getStats)
router.get('/recent-phishing', requireAdmin, getRecentPhishing)
router.get('/logs', requireAdmin, getLogs)
router.get('/models', requireAdmin, getModels)
router.get('/model/:modelId/evaluations', requireAdmin, getModelEvaluations)

export default router