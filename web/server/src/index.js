import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import dotenv from 'dotenv'
import { PrismaClient } from '@prisma/client'

// initialize
dotenv.config()
const app = express()
const prisma = new PrismaClient()
const PORT = process.env.WEB_SERVER_PORT

// middleware
app.use(helmet())
app.use(cors({
  origin: process.env.WEB_CLIENT_URL,
  credentials: true
}))
app.use(express.json())
app.use(morgan('dev'))

// health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() })
})

// root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'Phisher Chatbot API',
    version: '1.0.0',
    endpoints: ['/health', '/api/chat', '/api/url', '/api/report']
  })
})

// global error handler
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({
    error: 'Server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
  })
})

// start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

// handle shutdown
process.on('SIGINT', async () => {
  await prisma.$disconnect()
  console.log('Database connection closed')
  process.exit(0)
})