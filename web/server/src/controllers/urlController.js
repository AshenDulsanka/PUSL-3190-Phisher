import { v4 as uuidv4 } from 'uuid'
import { PrismaClient } from '@prisma/client'
import axios from 'axios'

const prisma = new PrismaClient()
const EXTENSION_API_ENDPOINT = process.env.EXTENSION_API_ENDPOINT
const CHATBOT_API_ENDPOINT = process.env.CHATBOT_API_ENDPOINT

// analyze a URL for phishing indicators with option for deep analysis
export const analyzeUrl = async (req, res) => {
  try {
    const { url, deepAnalysis = false } = req.body

    if (!url) {
      return res.status(400).json({ message: 'URL is required' })
    }

    // first check if we've already analyzed this URL
    const existingUrl = await prisma.uRL.findUnique({
      where: { url }
    })

    if (existingUrl && !deepAnalysis) {
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

    // choose appropriate API endpoint based on analysis depth
    const apiEndpoint = deepAnalysis ? CHATBOT_API_ENDPOINT : EXTENSION_API_ENDPOINT

    // call the ML API to analyze the URL
    const response = await axios.post(apiEndpoint, {
      url,
      client: deepAnalysis ? 'chatbot' : 'web_client'
    })
    const analysisResult = response.data

    // check if URL already exists 
    const updatedUrl = await prisma.uRL.findUnique({
      where: { url }
    })

    // define urlData to ensure its available in all code paths
    const urlData = {
      url,
      isPhishing: analysisResult.is_phishing,
      suspiciousScore: analysisResult.threat_score,
      usingIP: analysisResult.features?.UsingIP === 1 || analysisResult.features?.using_ip === 1,
      urlLength: analysisResult.features?.url_length || null,
      hasHTTPS: analysisResult.features?.uses_http === 0 || null,
      numDots: analysisResult.features?.num_dots || null,
      numHyphens: analysisResult.features?.num_hyphens || null,
      numSubdomains: analysisResult.features?.num_subdomains || null,
      hasAtSymbol: analysisResult.features?.Symbol === 1 || analysisResult.features?.has_at_symbol === 1,
      hasSpecialChars: analysisResult.features?.AbnormalURL === 1 || analysisResult.features?.has_special_chars === 1,
      
      // additional fields for deep analysis
      domainAge: deepAnalysis ? (analysisResult.deep_analysis?.domain_age_days || null) : null,
      hasIframe: deepAnalysis ? (analysisResult.deep_analysis?.content_analysis?.iframe_count > 0) : null,
      disablesRightClick: deepAnalysis ? (analysisResult.features?.disables_right_click || null) : null,
      hasPopup: deepAnalysis ? (analysisResult.features?.has_popup || null) : null,
      isShortened: analysisResult.features?.is_shortened || null,
    }

    if (updatedUrl) {
      // URL already exists, just update it and create detection session
      await prisma.uRL.update({
        where: { id: updatedUrl.id },
        data: urlData
      })
      
      await prisma.detectionSession.create({
        data: {
          sessionId: uuidv4(),
          urlId: updatedUrl.id,
          browserInfo: req.headers['user-agent'] || null,
          ipAddress: req.ip || null
        }
      })
    } else {
      // create new URL record with detection session
      await prisma.uRL.create({
        data: {
          ...urlData,
          detectionSessions: {
            create: {
              sessionId: uuidv4(),
              browserInfo: req.headers['user-agent'] || null,
              ipAddress: req.ip || null
            }
          }
        }
      })
    }

    // return analysis result with extracted features
    res.status(200).json({
      url,
      isPhishing: analysisResult.is_phishing,
      threatScore: analysisResult.threat_score,
      probability: analysisResult.probability,
      details: analysisResult.explanation || analysisResult.details,
      features: {
        // surface key features in a normalized format
        usingIP: analysisResult.features?.UsingIP === 1 || analysisResult.features?.using_ip === 1 || false,
        hasAtSymbol: analysisResult.features?.Symbol === 1 || analysisResult.features?.has_at_symbol === 1 || false,
        hasDash: analysisResult.features?.['PrefixSuffix-'] === 1 || false,
        numSubdomains: analysisResult.features?.SubDomains || analysisResult.features?.num_subdomains || 0,
        urlLength: analysisResult.features?.url_length || analysisResult.deep_analysis?.content_analysis?.url_length || 0,
        hasHTTPS: url.startsWith('https://') || analysisResult.features?.uses_https === true || false,
        domainAge: analysisResult.features?.AgeofDomain === 1 || (analysisResult.deep_analysis?.domain_age_days < 180) || false,
        hasSpecialChars: analysisResult.features?.AbnormalURL === 1 || false,
        isTyposquatting: analysisResult.features?.IsTyposquatting === 1 || analysisResult.deep_analysis?.typosquatting_info?.is_typosquatting || false,
        hasSuspiciousRedirect: analysisResult.features?.RequestURL === 1 || false,
        hasIframe: analysisResult.deep_analysis?.content_analysis?.iframe_count > 0 || false,
        suspiciousURL: analysisResult.features?.suspiciousURL || analysisResult.threat_score > 50,
        suspiciousDomain: analysisResult.features?.BrandInSubdomain === 1 || analysisResult.deep_analysis?.brand_impersonation?.detected || false
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