import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Box, Container, Typography, TextField, Button, 
  Paper, CircularProgress, InputAdornment
} from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';
import SearchIcon from '@mui/icons-material/Search';
import LinkIcon from '@mui/icons-material/Link';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import urlAnalysisService from '../services/urlAnalysisService';

const Home = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [quickResult, setQuickResult] = useState(null);

  const handleAnalyzeUrl = async () => {
    if (!url) {
      setError('Please enter a URL');
      return;
    }

    // Simple URL validation
    if (!url.match(/^(http|https):\/\/[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/.*)?$/)) {
      setError('Please enter a valid URL (including http:// or https://)');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const result = await urlAnalysisService.analyzeUrl(url);
      
      // Show quick result
      setQuickResult(result);
      
      // Navigate to detailed result page after a short delay
      setTimeout(() => {
        navigate('/results', { state: { result } });
      }, 1500);
      
    } catch (err) {
      console.error('Error analyzing URL:', err);
      setError('Failed to analyze URL. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md">
      <Box 
        sx={{ 
          mt: { xs: 4, md: 8 }, 
          display: 'flex', 
          flexDirection: 'column', 
          alignItems: 'center'
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
          <ShieldIcon sx={{ color: 'primary.main', mr: 2, fontSize: { xs: '2.5rem', md: '4rem' } }} />
          <Typography 
            variant="h2" 
            component="h1" 
            sx={{ 
              fontWeight: 600,
              fontSize: { xs: '2rem', sm: '3rem', md: '4rem' }
            }}
          >
            Phisher
          </Typography>
        </Box>

        <Typography 
          variant="h4" 
          sx={{ 
            mb: 2,
            textAlign: 'center',
            fontSize: { xs: '1.5rem', sm: '2rem', md: '2.5rem' }
          }}
        >
          AI-Powered URL Phishing Detection
        </Typography>
        
        <Typography 
          variant="body1" 
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
                bgcolor: quickResult.isPhishing ? 'error.light' : 'success.light'
              }}
            >
              {quickResult.isPhishing ? (
                <>
                  <WarningIcon sx={{ color: 'error.dark', mr: 1 }} />
                  <Typography color="error.dark" variant="h6">
                    Warning: Potential phishing URL detected
                  </Typography>
                </>
              ) : (
                <>
                  <CheckCircleIcon sx={{ color: 'success.dark', mr: 1 }} />
                  <Typography color="success.dark" variant="h6">
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
  );
};

export default Home;