import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

const urlAnalysisService = {
  analyzeUrl: async (url) => {
    const response = await api.post('/url/analyze', { url })
    return response.data
  },
  
  reportUrl: async (data) => {
    const response = await api.post('/url/report', data)
    return response.data
  },
  
  getRecentAnalyses: async () => {
    const response = await api.get('/url/recent')
    return response.data
  }
}

export default urlAnalysisService