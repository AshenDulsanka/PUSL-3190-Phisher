import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import process from 'node:process'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file based on mode
  const env = loadEnv(mode, process.cwd())
  
  // Use API URL from env or fallback to default
  const apiUrl = env.VITE_API_URL || 'http://web_server:5000'
  
  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      port: 3000,
      strictPort: true,
      watch: {
        usePolling: true,
      },
      proxy: {
        // proxy API requests to the backend server
        '/api': {
          target: apiUrl,
          changeOrigin: true,
          secure: false
        }
      }
    }
  }
})
