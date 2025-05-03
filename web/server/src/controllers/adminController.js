import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// admin login
export const login = async (req, res) => {
  console.log('Admin login attempt:', req.body.username)
  
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' })
    }

    // find admin by username
    const admin = await prisma.admin.findUnique({
      where: { username }
    })

    if (!admin) {
      console.log('Admin not found:', username)
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // compare passwords
    const passwordMatch = await bcrypt.compare(password, admin.password)

    if (!passwordMatch) {
      console.log('Password mismatch for admin:', username)
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // update last login time
    await prisma.admin.update({
      where: { id: admin.id },
      data: { lastLoginAt: new Date() }
    })

    // generate token
    const token = jwt.sign(
      { id: admin.id, username: admin.username, isAdmin: true },
      process.env.JWT_SECRET || 'default_jwt_secret',
      { expiresIn: '12h' }
    )

    console.log('Admin login successful:', username)
    
    res.status(200).json({
      token,
      user: {
        id: admin.id,
        username: admin.username,
        email: admin.email
      }
    })
  } catch (error) {
    console.error('Admin login error:', error)
    res.status(500).json({ message: 'Server error during login' })
  }
}

// get system stats for dashboard
export const getStats = async (req, res) => {
  try {
    const totalUrls = await prisma.uRL.count()
    const phishingUrls = await prisma.uRL.count({
      where: { isPhishing: true }
    })
    
    // get false positives (reported as false positive through URLReport)
    const falsePositives = await prisma.uRLReport.count({
      where: { reportType: 'false_positive' }
    })
    
    // calculate accuracy 
    const accuracy = totalUrls > 0 
      ? Math.round(((totalUrls - falsePositives) / totalUrls) * 100) 
      : 100
    
    res.status(200).json({
      totalUrls,
      phishingUrls,
      falsePositives,
      accuracy
    })
  } catch (error) {
    console.error('Stats error:', error)
    res.status(500).json({ message: 'Error retrieving stats' })
  }
}

// get recent phishing URLs
export const getRecentPhishing = async (req, res) => {
  try {
    const recentPhishing = await prisma.uRL.findMany({
      where: { isPhishing: true },
      orderBy: { createdAt: 'desc' },
      take: 10
    })
    
    res.status(200).json(recentPhishing)
  } catch (error) {
    console.error('Recent phishing error:', error)
    res.status(500).json({ message: 'Error retrieving recent phishing URLs' })
  }
}

// get system logs
export const getLogs = async (req, res) => {
  try {
    const { component, logLevel, search } = req.query
    
    // build filters
    const where = {}
    if (component) where.component = component
    if (logLevel) where.logLevel = logLevel
    if (search) where.message = { contains: search }
    
    const logs = await prisma.systemLog.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      take: 100
    })
    
    res.status(200).json(logs)
  } catch (error) {
    console.error('Logs error:', error)
    res.status(500).json({ message: 'Error retrieving logs' })
  }
}