import express from 'express'
import { 
    login, 
    getStats, 
    getRecentPhishing, 
    getLogs, 
    getModels, 
    getModelEvaluations, 
    updateModel, 
    getPhishingUrls,
    getTrends 
} from '../controllers/adminController.js'
import { requireAdmin } from '../middleware/auth.js'
import rateLimit from 'express-rate-limit'

const router = express.Router()

// Configure rate limiter: maximum of 100 requests per 15 minutes
const adminRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
})

// public routes
router.post('/login', login)

// protected routes
router.get('/stats', adminRateLimiter, requireAdmin, getStats)
router.get('/recent-phishing', adminRateLimiter, requireAdmin, getRecentPhishing)
router.get('/logs', adminRateLimiter, requireAdmin, getLogs)
router.get('/models', adminRateLimiter, requireAdmin, getModels)
router.get('/model/:modelId/evaluations', adminRateLimiter, requireAdmin, getModelEvaluations)
router.put('/model/:modelId/update', adminRateLimiter, requireAdmin, updateModel)
router.get('/phishing-urls', adminRateLimiter, requireAdmin, getPhishingUrls)
router.get('/trends', adminRateLimiter, requireAdmin, getTrends)

export default router