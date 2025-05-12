import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import dotenv from 'dotenv'
import { PrismaClient } from '@prisma/client'

// import routes
import urlRoutes from './routes/urlRoutes.js'
import adminRoutes from './routes/adminRoutes.js'

// initialize
dotenv.config()
const app = express()
const prisma = new PrismaClient()
const PORT = parseInt(process.env.PORT || process.env.WEB_SERVER_PORT || '8080', 10)

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err)
})

// middleware
app.use(helmet())
app.use(cors({
  origin: process.env.WEB_CLIENT_URL,
  credentials: true
}))
app.use(express.json())
app.use(morgan('dev'))

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
    message: 'Phisher Chatbot API',
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
    // test the connection
    await prisma.$connect()
    console.info('Successfully connected to database')
    return true
  } catch (error) {
    console.error('Failed to connect to database:', error)
    return false
  }
}

// debugging logs
console.info(`Current environment: ${process.env.NODE_ENV}`)
console.info(`PORT environment variable: ${process.env.PORT}`)
console.info(`Attempting to start server on port ${PORT} and host 0.0.0.0`)

// start server
app.listen(PORT, '0.0.0.0', async () => {
  console.info(`Server started and listening on http://0.0.0.0:${PORT}`)
  
  try {
    await connectToDatabase()
    console.info('Database connection successful')
  } catch (error) {
    console.error('Database connection failed:', error)
  }
})

// handle shutdown
process.on('SIGINT', async () => {
  await prisma.$disconnect()
  console.info('Database connection closed')
  process.exit(0)
})
