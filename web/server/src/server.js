process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err)
})

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason)
})

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
const PORT = parseInt(process.env.PORT || process.env.WEB_SERVER_PORT || '8080', 10)

// middleware
app.use(helmet())
app.use(cors({
  origin: process.env.WEB_CLIENT_URL || '*',
  credentials: true
}))
app.use(express.json())
app.use(morgan('dev'))

// import routes
import urlRoutes from './routes/urlRoutes.js'
import adminRoutes from './routes/adminRoutes.js'

// routes
app.use('/api/url', urlRoutes)
app.use('/api/url/admin', adminRoutes)

// health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() })
})

// root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'Phisher API',
    version: '1.0.0',
    endpoints: ['/health', '/api/url', '/api/url/admin']
  })
})

// global error handler
app.use((err, req, res) => {
  console.error(err.stack)
  res.status(500).json({
    error: 'Server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
  })
})

const connectToDatabase = async () => {
  try {
    await prisma.$connect()
    console.info('Successfully connected to database')
    return true
  } catch (error) {
    console.error('Failed to connect to database:', error)
    return false
  }
}

// detailed logging
console.info('Starting server with:')
console.info(`- Environment: ${process.env.NODE_ENV || 'development'}`)
console.info(`- Port: ${PORT}`)
console.info(`- Database URL format: ${process.env.DATABASE_URL ? 'Exists (correct format)' : 'MISSING!'}`)

// bind to 0.0.0.0 (all interfaces)
app.listen(PORT, '0.0.0.0', async () => {
  console.info(`Server started and listening on http://0.0.0.0:${PORT}`)
  
  try {
    const connected = await connectToDatabase()
    if (connected) {
      console.info('Database connection established successfully')
    } else {
      console.warn('Server running but database connection failed - will retry as needed')
    }
  } catch (error) {
    console.error('Database initialization error:', error)
  }
})

// handle graceful shutdown
process.on('SIGINT', async () => {
  console.info('Received SIGINT, shutting down gracefully...')
  await prisma.$disconnect()
  console.info('Database connection closed')
  process.exit(0)
})
