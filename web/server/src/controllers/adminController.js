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
    
    // get false negatives (reported as false negative or missed phishing)
    const falseNegatives = await prisma.uRLReport.count({
      where: { reportType: 'false_negative' }
    })
    
    // calculate accuracy
    const totalReports = falsePositives + falseNegatives
    const accuracy = totalUrls > 0 && totalReports > 0
      ? Math.round(((totalUrls - totalReports) / totalUrls) * 100)
      : 100
    
    res.status(200).json({
      totalUrls,
      phishingUrls,
      falsePositives,
      falseNegatives,
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

export const getModels = async (req, res) => {
  try {
    const models = await prisma.mLModel.findMany({
      orderBy: { trainedAt: 'desc' }
    })
    
    res.status(200).json(models)
  } catch (error) {
    console.error('Models error:', error)
    res.status(500).json({ message: 'Error retrieving models' })
  }
}

export const getModelEvaluations = async (req, res) => {
  try {
    const { modelId } = req.params
    
    if (!modelId || isNaN(parseInt(modelId))) {
      return res.status(400).json({ message: 'Valid model ID is required' })
    }
    
    const evaluations = await prisma.modelEvaluation.findMany({
      where: { modelId: parseInt(modelId) },
      orderBy: { evaluatedAt: 'desc' },
      take: 50,
      include: {
        url: {
          select: {
            url: true,
            isPhishing: true
          }
        }
      }
    })
    
    res.status(200).json(evaluations)
  } catch (error) {
    console.error('Model evaluations error:', error)
    res.status(500).json({ message: 'Error retrieving model evaluations' })
  }
}

export const updateModel = async (req, res) => {
  try {
    const { modelId } = req.params
    const { accuracy, precision, recall, f1Score, areaUnderROC, feedbackIncorporated } = req.body
    
    if (!modelId || isNaN(parseInt(modelId))) {
      return res.status(400).json({ message: 'Valid model ID is required' })
    }
    
    const updatedModel = await prisma.mLModel.update({
      where: { id: parseInt(modelId) },
      data: {
        accuracy,
        precision,
        recall,
        f1Score,
        areaUnderROC,
        feedbackIncorporated,
        lastUpdated: new Date()
      }
    })
    
    // log model update
    await prisma.systemLog.create({
      data: {
        component: 'admin',
        logLevel: 'info',
        message: `Model ${updatedModel.name} metrics updated by admin`,
        timestamp: new Date(),
        metadata: JSON.stringify({
          modelId: updatedModel.id,
          changes: {
            accuracy,
            precision,
            recall,
            f1Score,
            areaUnderROC,
            feedbackIncorporated
          }
        })
      }
    })
    
    res.status(200).json(updatedModel)
  } catch (error) {
    console.error('Model update error:', error)
    res.status(500).json({ message: 'Error updating model' })
  }
}

export const getPhishingUrls = async (req, res) => {
  try {
    const phishingUrls = await prisma.uRL.findMany({
      where: { isPhishing: true },
      orderBy: { createdAt: 'desc' },
      take: 100
    })
    
    res.status(200).json(phishingUrls)
  } catch (error) {
    console.error('Phishing URLs error:', error)
    res.status(500).json({ message: 'Error retrieving phishing URLs' })
  }
}