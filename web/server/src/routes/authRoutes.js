import express from 'express'
import { register, login, validateToken } from '../controllers/authController.js'
import { authMiddleware } from '../middleware/auth.js'

const router = express.Router()

// public routes
router.post('/register', register)
router.post('/login', login)

// protected routes
router.get('/validate', authMiddleware, validateToken)

export default router