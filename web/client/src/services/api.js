import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// add authentication token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// auth services
export const authService = {
  register: async (userData) => {
    const response = await api.post('/api/auth/register', userData)
    return response.data
  },
  
  login: async (credentials) => {
    const response = await api.post('/api/auth/login', credentials)
    return response.data
  },
  
  validateToken: async () => {
    const response = await api.get('/api/auth/validate')
    return response.data
  },
}

export default api