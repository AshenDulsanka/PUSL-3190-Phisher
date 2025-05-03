import databaseService from '../services/databaseService.js'

const logger = {
  info: async (component, message, metadata = {}) => {
    console.info(`[INFO][${component}] ${message}`)
    await databaseService.logSystemEvent(component, 'info', message, metadata)
  },
  
  warning: async (component, message, metadata = {}) => {
    console.warn(`[WARNING][${component}] ${message}`)
    await databaseService.logSystemEvent(component, 'warning', message, metadata)
  },
  
  error: async (component, message, error = null) => {
    const metadata = error ? { errorMessage: error.message, stack: error.stack } : {}
    console.error(`[ERROR][${component}] ${message}`, error || '')
    await databaseService.logSystemEvent(component, 'error', message, metadata)
  },
  
  debug: async (component, message, metadata = {}) => {
    console.debug(`[DEBUG][${component}] ${message}`)
    await databaseService.logSystemEvent(component, 'debug', message, metadata)
  }
}

export default logger