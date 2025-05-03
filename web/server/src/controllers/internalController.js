import databaseService from '../services/databaseService.js'

// save URL analysis from internal services
export const saveURLAnalysis = async (req, res) => {
  try {
    const { url, is_phishing, threat_score, source, features } = req.body
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' })
    }
    
    const urlData = {
      url,
      is_phishing: Boolean(is_phishing),
      threat_score: Number(threat_score) || 0
    }
    
    const detectionInfo = {
      source: source || 'internal',
      // Additional info could be added here
    }
    
    const result = await databaseService.saveURLAnalysis(urlData, features || {}, detectionInfo)
    
    res.status(200).json({
      success: true,
      url_id: result.id
    })
  } catch (error) {
    console.error('Error saving URL analysis:', error)
    res.status(500).json({ error: 'Failed to save URL analysis' })
  }
}

// process batch of feedback from Redis
export const processFeedbackBatch = async (req, res) => {
  try {
    const { feedback_batch } = req.body
    
    if (!feedback_batch || !Array.isArray(feedback_batch)) {
      return res.status(400).json({ error: 'Valid feedback batch is required' })
    }
    
    const results = await databaseService.processFeedbackQueue(feedback_batch)
    
    res.status(200).json({
      success: true,
      processed: results.filter(r => r.success).length,
      total: feedback_batch.length,
      results: results
    })
  } catch (error) {
    console.error('Error processing feedback batch:', error)
    res.status(500).json({ error: 'Failed to process feedback batch' })
  }
}

// log system event
export const logSystemEvent = async (req, res) => {
  try {
    const { component, logLevel, message, metadata } = req.body
    
    if (!component || !logLevel || !message) {
      return res.status(400).json({ error: 'Component, log level, and message are required' })
    }
    
    await databaseService.logSystemEvent(component, logLevel, message, metadata)
    
    res.status(200).json({ success: true })
  } catch (error) {
    console.error('Error logging system event:', error)
    res.status(500).json({ error: 'Failed to log system event' })
  }
}

// get model metrics
export const getModelMetrics = async (req, res) => {
  try {
    const { modelName } = req.params
    
    if (!modelName) {
      return res.status(400).json({ error: 'Model name is required' })
    }
    
    const metrics = await databaseService.getModelMetrics(modelName)
    
    if (!metrics) {
      return res.status(404).json({ error: 'Model not found' })
    }
    
    res.status(200).json(metrics)
  } catch (error) {
    console.error('Error getting model metrics:', error)
    res.status(500).json({ error: 'Failed to get model metrics' })
  }
}

// register or update ML model
export const registerModel = async (req, res) => {
  try {
    const { name, type, version, parameters } = req.body
    
    if (!name) {
      return res.status(400).json({ error: 'Model name is required' })
    }
    
    // check if model exists
    let model = await databaseService.prisma.mLModel.findUnique({
      where: { name }
    })
    
    // create or update
    if (model) {
      model = await databaseService.prisma.mLModel.update({
        where: { id: model.id },
        data: {
          type: type || model.type,
          version: version || model.version,
          parameters: parameters || model.parameters
        }
      })
    } else {
      model = await databaseService.prisma.mLModel.create({
        data: {
          name,
          type: type || 'unknown',
          version: version || '1.0',
          parameters: parameters || null
        }
      })
    }
    
    res.status(200).json({
      success: true,
      model: model
    })
  } catch (error) {
    console.error('Error registering model:', error)
    res.status(500).json({ error: 'Failed to register model' })
  }
}

// track model evaluation
export const trackModelEvaluation = async (req, res) => {
  try {
    const { model_name, url, predicted_score, actual_label } = req.body
    
    if (!model_name || !url || predicted_score === undefined) {
      return res.status(400).json({ error: 'Missing required fields' })
    }
    
    // find the model
    const model = await databaseService.prisma.mLModel.findUnique({
      where: { name: model_name }
    })
    
    if (!model) {
      return res.status(404).json({ error: 'Model not found' })
    }
    
    // find the URL
    let urlRecord = await databaseService.prisma.uRL.findUnique({
      where: { url }
    })
    
    // create the URL if it doesn't exist
    if (!urlRecord) {
      urlRecord = await databaseService.prisma.uRL.create({
        data: {
          url,
          isPhishing: Boolean(actual_label),
          suspiciousScore: predicted_score * 100, // 0-1 to 0-100
          analysisSources: ['evaluation']
        }
      })
    }
    
    // record the evaluation
    const evaluation = await databaseService.prisma.modelEvaluation.create({
      data: {
        predictedScore: predicted_score,
        actualLabel: actual_label === null ? undefined : Boolean(actual_label),
        modelId: model.id,
        urlId: urlRecord.id
      }
    })
    
    res.status(200).json({ success: true, evaluation })
  } catch (error) {
    console.error('Error tracking model evaluation:', error)
    res.status(500).json({ error: 'Failed to track model evaluation' })
  }
}