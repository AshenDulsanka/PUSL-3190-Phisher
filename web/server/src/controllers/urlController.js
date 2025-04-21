import { v4 as uuidv4 } from 'uuid'
import { PrismaClient } from '@prisma/client'
import axios from 'axios'

const prisma = new PrismaClient()
const ML_API_ENDPOINT = process.env.ML_API_ENDPOINT

// analyze a URL for phishing indicators
export const analyzeUrl = async (req, res) => {
  try {
    const { url } = req.body

    if (!url) {
      return res.status(400).json({ message: 'URL is required' })
    }

    // first check if we've already analyzed this URL
    const existingUrl = await prisma.uRL.findUnique({
      where: { url }
    })

    if (existingUrl) {
      // create a new detection session for this URL
      await prisma.detectionSession.create({
        data: {
          sessionId: uuidv4(),
          urlId: existingUrl.id,
          browserInfo: req.headers['user-agent'] || null,
          ipAddress: req.ip || null
        }
      })

      // return cached result
      return res.status(200).json({
        url,
        isPhishing: existingUrl.isPhishing,
        threatScore: existingUrl.suspiciousScore,
        probability: existingUrl.suspiciousScore / 100,
        details: `This URL was previously analyzed and ${existingUrl.isPhishing ? 'identified as phishing' : 'appears to be legitimate'}.`,
        features: {
          usingIP: existingUrl.usingIP,
          urlLength: existingUrl.urlLength,
          hasAtSymbol: existingUrl.hasAtSymbol,
          hasDash: existingUrl.numHyphens > 0,
          numSubdomains: existingUrl.numSubdomains,
          hasHTTPS: existingUrl.hasHTTPS,
          hasSpecialChars: existingUrl.hasSpecialChars
        }
      })
    }

    // call the ML API to analyze the URL
    const response = await axios.post(ML_API_ENDPOINT, { url })
    const analysisResult = response.data

    // store URL analysis result in database
    const newUrl = await prisma.uRL.create({
      data: {
        url,
        isPhishing: analysisResult.is_phishing,
        suspiciousScore: analysisResult.threat_score,
        usingIP: analysisResult.features?.using_ip || null,
        urlLength: analysisResult.features?.url_length || null,
        hasHTTPS: analysisResult.features?.has_https || null,
        numDots: analysisResult.features?.num_dots || null,
        numHyphens: analysisResult.features?.num_hyphens || null,
        numSubdomains: analysisResult.features?.num_subdomains || null,
        hasAtSymbol: analysisResult.features?.has_at_symbol || null,
        hasSpecialChars: analysisResult.features?.has_special_chars || null,
        detectionSessions: {
          create: {
            sessionId: uuidv4(),
            browserInfo: req.headers['user-agent'] || null,
            ipAddress: req.ip || null
          }
        }
      }
    })

    // return analysis result
    res.status(200).json({
      url,
      isPhishing: analysisResult.is_phishing,
      threatScore: analysisResult.threat_score,
      probability: analysisResult.probability,
      details: analysisResult.details,
      features: {
        usingIP: analysisResult.features?.using_ip || false,
        urlLength: analysisResult.features?.url_length || 0,
        hasAtSymbol: analysisResult.features?.has_at_symbol || false,
        hasDash: (analysisResult.features?.num_hyphens || 0) > 0,
        numSubdomains: analysisResult.features?.num_subdomains || 0,
        hasHTTPS: analysisResult.features?.has_https || false,
        hasSpecialChars: analysisResult.features?.has_special_chars || false
      }
    })
  } catch (error) {
    console.error('URL analysis error:', error)
    res.status(500).json({ message: 'Error analyzing URL' })
  }
}

// report incorrect analysis
export const reportUrl = async (req, res) => {
  try {
    const { url, reportType, comments, reporterEmail } = req.body

    if (!url || !reportType) {
      return res.status(400).json({ message: 'URL and report type are required' })
    }

    // find the URL in the database
    const urlRecord = await prisma.uRL.findUnique({
      where: { url }
    })

    // create the report
    await prisma.uRLReport.create({
      data: {
        reportedUrl: url,
        reportType,
        comments,
        reporterEmail,
        urlId: urlRecord?.id || null
      }
    })

    res.status(201).json({ message: 'Report submitted successfully' })
  } catch (error) {
    console.error('URL report error:', error)
    res.status(500).json({ message: 'Error submitting report' })
  }
}

// get recent URL analyses
export const getRecentAnalyses = async (req, res) => {
  try {
    const recentAnalyses = await prisma.uRL.findMany({
      take: 10,
      orderBy: {
        createdAt: 'desc'
      },
      select: {
        url: true,
        isPhishing: true,
        suspiciousScore: true,
        createdAt: true
      }
    })

    res.status(200).json(recentAnalyses)
  } catch (error) {
    console.error('Recent analyses error:', error)
    res.status(500).json({ message: 'Error fetching recent analyses' })
  }
}