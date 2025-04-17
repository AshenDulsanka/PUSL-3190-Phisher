import express from 'express'
import { register, login, validateToken } from '../controllers/authController.js'
import { authMiddleware } from '../middleware/auth.js'
import RateLimit from 'express-rate-limit'

const router = express.Router()

const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

// public routes
router.post('/register', register)
router.post('/login', login)

// protected routes
router.get('/validate', limiter, authMiddleware, validateToken)

export default router