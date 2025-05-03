import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Container, Box, Typography, TextField, Button, Paper, 
  CircularProgress, InputAdornment
} from '@mui/material'
import LinkIcon from '@mui/icons-material/Link'
import SearchIcon from '@mui/icons-material/Search'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import WarningIcon from '@mui/icons-material/Warning'
import urlAnalysisService from '../services/urlAnalysisService'

const Home = () => {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [quickResult, setQuickResult] = useState(null)
  const navigate = useNavigate()

  const handleAnalyzeUrl = async () => {
    if (!url) {
      setError('Please enter a URL')
      return
    }

    if (!url.match(/^(http|https):\/\/[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/.*)?$/)) {
      setError('Please enter a valid URL (including http:// or https://)')
      return
    }

    setLoading(true)
    setError('')
    try {
      // always perform deep analysis
      const result = await urlAnalysisService.analyzeUrl(url, true)
      setQuickResult(result)
      
      setTimeout(() => {
        navigate('/results', { state: { result } })
      }, 1500)
      
    } catch (err) {
      console.error('Error analyzing URL:', err)
      setError('Failed to analyze URL. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Container maxWidth="md">
      <Box 
        sx={{ 
          minHeight: '90vh',
          display: 'flex', 
          flexDirection: 'column',
          justifyContent: 'center', 
          alignItems: 'center',
          py: 4
        }}
      >
        <Box sx={{ 
          display: 'flex', 
          flexDirection: 'column',
          alignItems: 'center',
          mb: 4
        }}>
          <img 
            src="/logo-bg.png" 
            alt="Phisher Logo" 
            width={120} 
            height={120} 
            style={{ 
              marginBottom: '16px',
              objectFit: 'contain'
            }} 
          />
          <Typography 
            variant="h2" 
            component="h1" 
            sx={{ 
              fontWeight: 700, 
              textAlign: 'center',
              mb: 2 
            }}
          >
            Phishing URL Detector
          </Typography>
          
          <Typography 
            variant="body1" 
            color="text.secondary" 
            sx={{ 
              mb: 5, 
              maxWidth: '700px',
              textAlign: 'center',
              fontSize: { xs: '1rem', md: '1.25rem' } 
            }}
          >
            Protect yourself from phishing attacks with our advanced AI detection system. 
            Simply enter a URL and our machine learning model will analyze it for phishing indicators.
          </Typography>
        </Box>

        <Paper 
          elevation={3} 
          sx={{ 
            width: '100%', 
            p: { xs: 2, sm: 3, md: 4 },
            borderRadius: 2,
            mb: 4
          }}
        >
          <Typography variant="h5" sx={{ mb: 2 }}>
            Analyze a URL
          </Typography>
          
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Enter a URL to analyze (e.g., https://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            error={!!error}
            helperText={error}
            disabled={loading}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <LinkIcon />
                </InputAdornment>
              ),
            }}
            sx={{ mb: 3 }}
          />
          
          <Button
            variant="contained"
            fullWidth
            size="large"
            onClick={handleAnalyzeUrl}
            disabled={loading}
            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SearchIcon />}
            sx={{ py: 1.5 }}
          >
            {loading ? 'Analyzing...' : 'Analyze URL'}
          </Button>

          {quickResult && (
            <Box 
              sx={{ 
                mt: 3, 
                p: 2, 
                borderRadius: 2, 
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                bgcolor: quickResult.threatScore > 50 ? 'error.dark' : 
                         quickResult.threatScore > 30 ? 'warning.dark' : 'success.dark'
              }}
            >
              {quickResult.threatScore > 50 ? (
                <>
                  <WarningIcon sx={{ color: 'error.light', mr: 1 }} />
                  <Typography color="error.light" variant="h6">
                    Warning: Phishing URL detected
                  </Typography>
                </>
              ) : quickResult.threatScore > 30 ? (
                <>
                  <WarningIcon sx={{ color: 'warning.light', mr: 1 }} />
                  <Typography color="warning.light" variant="h6">
                    Suspicious URL detected
                  </Typography>
                </>
              ) : (
                <>
                  <CheckCircleIcon sx={{ color: 'success.light', mr: 1 }} />
                  <Typography color="success.light" variant="h6">
                    URL appears to be safe
                  </Typography>
                </>
              )}
            </Box>
          )}
        </Paper>

        <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', mb: 2 }}>
          Our system uses advanced machine learning algorithms to detect phishing attempts.
        </Typography>
        
        <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center' }}>
          For educational use only. Always exercise caution when visiting unfamiliar websites.
        </Typography>
      </Box>
    </Container>
  )
}

export default Home