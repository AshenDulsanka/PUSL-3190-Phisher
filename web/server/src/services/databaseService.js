import { PrismaClient } from '@prisma/client'
import { v4 as uuidv4 } from 'uuid'

class DatabaseService {
  constructor() {
    this.prisma = new PrismaClient()
  }

  // URL operations
  async saveURLAnalysis(urlData, features, detectionInfo = {}) {
    try {
      // first check if URL already exists
      const existingURL = await this.prisma.uRL.findUnique({
        where: { url: urlData.url }
      })

      // extract feature data
      const featureData = {
        usingIP: features.usingIP || features.has_ip || null,
        urlLength: features.urlLength || features.url_length || null,
        domainAge: features.domainAge || features.domain_age || null,
        hasHTTPS: features.hasHTTPS || (features.uses_http === 0) || null,
        numDots: features.numDots || features.num_dots || null,
        numHyphens: features.numHyphens || features.num_hyphens || null,
        numSubdomains: features.numSubdomains || features.sub_domains || null,
        hasAtSymbol: features.hasAtSymbol || features.has_at_symbol || null,
        isShortened: features.isShortened || features.is_shortened || null,
        hasSpecialChars: features.hasSpecialChars || features.has_special_chars || null,
        hasIframe: features.hasIframe || features.has_iframe || null,
        disablesRightClick: features.disablesRightClick || null,
        hasPopup: features.hasPopup || features.has_popup || null,
      }

      // prepare source tracking
      const source = detectionInfo.source || 'unknown'
      let sources = existingURL?.analysisSources || []
      if (!sources.includes(source)) {
        sources.push(source)
      }

      // create or update URL record
      const urlRecord = existingURL 
        ? await this.prisma.uRL.update({
            where: { id: existingURL.id },
            data: {
              isPhishing: urlData.is_phishing,
              suspiciousScore: urlData.threat_score,
              updatedAt: new Date(),
              lastAnalyzed: new Date(),
              analysisSources: sources,
              analyzeCount: { increment: 1 },
              detectedPhishingCount: urlData.is_phishing 
                ? { increment: 1 } 
                : undefined,
              ...featureData
            }
          })
        : await this.prisma.uRL.create({
            data: {
              url: urlData.url,
              isPhishing: urlData.is_phishing,
              suspiciousScore: urlData.threat_score,
              analysisSources: [source],
              ...featureData
            }
          })
      
      // create detection session record if browser info provided
      if (detectionInfo.browserInfo || detectionInfo.ipAddress) {
        await this.prisma.detectionSession.create({
          data: {
            sessionId: detectionInfo.sessionId || uuidv4(),
            browserInfo: detectionInfo.browserInfo,
            ipAddress: detectionInfo.ipAddress,
            urlId: urlRecord.id
          }
        })
      }

      return urlRecord
    } catch (error) {
      console.error('Error saving URL analysis:', error)
      throw error
    }
  }
  
  // feedback/report operations
  async saveFeedback(feedbackData) {
    try {
      // find URL if it exists
      const existingURL = await this.prisma.uRL.findUnique({
        where: { url: feedbackData.url }
      })

      // create the feedback record
      const report = await this.prisma.uRLReport.create({
        data: {
          reportedUrl: feedbackData.url,
          reportType: feedbackData.feedback_type,
          comments: feedbackData.comments,
          reporterEmail: feedbackData.reported_by,
          source: feedbackData.source,
          urlId: existingURL?.id || null
        }
      })

      return report
    } catch (error) {
      console.error('Error saving feedback:', error)
      throw error
    }
  }
  
  // system logging
  async logSystemEvent(component, level, message, metadata = {}) {
    try {
      console.log(`Logging system event: ${component} - ${level} - ${message}`)
      
      // ensure metadata is properly serialized if its an object
      let metadataString = null
      if (metadata) {
        try {
          metadataString = typeof metadata === 'string' ? metadata : JSON.stringify(metadata)
        } catch (e) {
          console.error('Error serializing metadata:', e)
          metadataString = JSON.stringify({ error: 'Could not serialize original metadata' })
        }
      }
  
      const result = await this.prisma.systemLog.create({
        data: {
          component,
          logLevel: level,
          message,
          metadata: metadataString
        }
      })
      
      console.log('Log saved with ID:', result.id)
      return result
    } catch (error) {
      console.error('Error logging system event:', error)
      // dont throw because this is a logging function
      return null
    }
  }
  
  // model tracking
  async trackModelEvaluation(modelName, urlData, prediction, actualLabel = null) {
    try {
      // get or create the model record
      let model = await this.prisma.mLModel.findUnique({
        where: { name: modelName }
      })
      
      if (!model) {
        const [name, version = '1.0'] = modelName.split('_v')
        model = await this.prisma.mLModel.create({
          data: {
            name: modelName,
            type: modelName.includes('random_forest') ? 'random_forest' : 
                 modelName.includes('neural') ? 'neural_network' : 'unknown',
            version: version
          }
        })
      }
      
      // find URL
      const url = await this.prisma.uRL.findUnique({
        where: { url: urlData.url }
      })
      
      if (!url) {
        throw new Error('URL not found for model evaluation')
      }
      
      // create evaluation record
      return await this.prisma.modelEvaluation.create({
        data: {
          predictedScore: prediction,
          actualLabel,
          modelId: model.id,
          urlId: url.id
        }
      })
    } catch (error) {
      console.error('Error tracking model evaluation:', error)
      return null
    }
  }
  
  // process feedback queue from Redis
  async processFeedbackQueue(feedbackBatch) {
    const results = []
    
    for (const feedback of feedbackBatch) {
      try {
        // save to feedback queue table
        const queueEntry = await this.prisma.feedbackQueue.create({
          data: {
            url: feedback.url,
            isPhishing: feedback.is_phishing,
            feedbackType: feedback.feedback_type,
            timestamp: new Date(feedback.timestamp * 1000), // Convert Unix timestamp
            processed: false
          }
        })
        
        // also save as a URL report
        await this.saveFeedback({
          url: feedback.url,
          feedback_type: feedback.feedback_type,
          comments: "From continuous learning queue",
          source: "redis_queue"
        })
        
        results.push({
          id: queueEntry.id,
          success: true
        })
      } catch (error) {
        results.push({
          url: feedback.url,
          success: false,
          error: error.message
        })
      }
    }
    
    return results
  }
  
  // mark feedback as processed
  async markFeedbackProcessed(ids) {
    try {
      await this.prisma.feedbackQueue.updateMany({
        where: { id: { in: ids } },
        data: { processed: true, processedAt: new Date() }
      })
      return true
    } catch (error) {
      console.error('Error marking feedback as processed:', error)
      return false
    }
  }

  // get model metrics for dashboard
  async getModelMetrics(modelName) {
    try {
      const model = await this.prisma.mLModel.findUnique({
        where: { name: modelName }
      })
      
      if (!model) {
        return null
      }
      
      return {
        model: model,
        evaluationCount: await this.prisma.modelEvaluation.count({
          where: { modelId: model.id }
        })
      }
    } catch (error) {
      console.error('Error getting model metrics:', error)
      return null
    }
  }

  // disconnect when done
  async disconnect() {
    await this.prisma.$disconnect()
  }
}

export default new DatabaseService()