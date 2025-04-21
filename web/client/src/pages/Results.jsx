import { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Box, Container, Typography, Paper, Button, Grid,
  Divider, List, ListItem, ListItemIcon, ListItemText,
  LinearProgress, Link, Alert
} from '@mui/material'
import SecurityIcon from '@mui/icons-material/Security'
import VerifiedIcon from '@mui/icons-material/Verified'
import DangerousIcon from '@mui/icons-material/Dangerous'
import ArrowBackIcon from '@mui/icons-material/ArrowBack'
import FlagIcon from '@mui/icons-material/Flag'
import LinkIcon from '@mui/icons-material/Link'
import HelpOutlineIcon from '@mui/icons-material/HelpOutline'
import CheckIcon from '@mui/icons-material/Check'
import CloseIcon from '@mui/icons-material/Close'
import urlAnalysisService from '../services/urlAnalysisService'

const Results = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const [result, setResult] = useState(null)
  const [reportSubmitted, setReportSubmitted] = useState(false)

  useEffect(() => {
    // if we don't have a result from navigation state, go back to home
    if (!location.state?.result) {
      navigate('/')
      return
    }
    
    setResult(location.state.result)
  }, [location, navigate])

  const handleReportUrl = async () => {
    try {
      await urlAnalysisService.reportUrl({
        url: result.url,
        reportType: result.isPhishing ? 'confirm_phishing' : 'false_negative',
      })
      setReportSubmitted(true)
    } catch (error) {
      console.error('Error reporting URL:', error)
    }
  }

  if (!result) {
    return (
      <Container>
        <Box sx={{ my: 4, textAlign: 'center' }}>
          <Typography variant="h5">Loading analysis results...</Typography>
          <LinearProgress sx={{ mt: 2 }} />
        </Box>
      </Container>
    )
  }

  const { 
    url, 
    isPhishing, 
    threatScore, 
    probability,
    details,
    features = {} 
  } = result

  // extract domain name from URL for display
  // eslint-disable-next-line no-unused-vars
  const domain = url.replace(/^https?:\/\//, '').split('/')[0]

  // map features to user-readable format
  const featureExplanations = {
    usingIP: 'Uses IP address instead of domain name',
    urlLength: 'URL is suspiciously long',
    hasAtSymbol: 'URL contains @ symbol',
    hasDoubleSlash: 'URL contains double slash in unusual location',
    hasDash: 'Domain contains dash (-)',
    numSubdomains: 'Number of subdomains',
    hasHTTPS: 'Uses HTTPS',
    domainAge: 'Domain registration age',
    hasSpecialChars: 'Contains unusual special characters'
  }

  return (
    <Container>
      <Box sx={{ mt: 4, mb: 6 }}>
        <Button 
          startIcon={<ArrowBackIcon />} 
          onClick={() => navigate('/')}
          sx={{ mb: 3 }}
        >
          Analyze Another URL
        </Button>

        <Paper elevation={3} sx={{ p: 4, borderRadius: 2 }}>
          <Box 
            sx={{ 
              display: 'flex', 
              alignItems: 'center',
              mb: 3
            }}
          >
            <SecurityIcon 
              color={isPhishing ? 'error' : 'success'} 
              sx={{ fontSize: 40, mr: 2 }} 
            />
            <Typography variant="h4" component="h1">
              URL Analysis Results
            </Typography>
          </Box>

          <Alert 
            severity={isPhishing ? 'error' : 'success'}
            icon={isPhishing ? <DangerousIcon /> : <VerifiedIcon />}
            sx={{ mb: 4, py: 2 }}
          >
            <Typography variant="h6">
              {isPhishing 
                ? 'Warning: This URL appears to be a phishing attempt!' 
                : 'This URL appears to be legitimate.'}
            </Typography>
          </Alert>

          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle1" color="text.secondary" gutterBottom>
              Analyzed URL:
            </Typography>
            <Typography 
              variant="body1" 
              component="div" 
              sx={{ 
                p: 2, 
                bgcolor: 'background.default',
                borderRadius: 1,
                wordBreak: 'break-all',
                fontFamily: 'monospace',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <LinkIcon sx={{ mr: 1, color: 'primary.main' }} />
              {url}
            </Typography>
          </Box>

          <Grid container spacing={4}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Threat Assessment
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Threat Score:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {threatScore}/100
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={threatScore} 
                  color={threatScore > 70 ? 'error' : threatScore > 30 ? 'warning' : 'success'}
                  sx={{ height: 10, borderRadius: 5 }}
                />
              </Box>
              
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Confidence:</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {(probability * 100).toFixed(2)}%
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={probability * 100} 
                  color="info"
                  sx={{ height: 10, borderRadius: 5 }}
                />
              </Box>

              <Typography variant="body1" sx={{ mt: 3, mb: 2 }}>
                {details || (isPhishing 
                  ? 'Our AI model has detected multiple suspicious characteristics in this URL that are commonly associated with phishing attempts.'
                  : 'Our analysis did not detect suspicious patterns typically associated with phishing attempts.'
                )}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                URL Features Analyzed
              </Typography>
              
              <List dense>
                {Object.entries(features).map(([key, value]) => (
                  <ListItem key={key} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      {typeof value === 'boolean' ? (
                        value ? 
                          <CheckIcon color={key === 'hasHTTPS' ? 'success' : 'error'} /> : 
                          <CloseIcon color={key === 'hasHTTPS' ? 'error' : 'inherit'} />
                      ) : (
                        <HelpOutlineIcon color="action" />
                      )}
                    </ListItemIcon>
                    <ListItemText 
                      primary={featureExplanations[key] || key}
                      secondary={typeof value === 'boolean' ? null : `Value: ${value}`}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              Is this analysis incorrect?
            </Typography>
            
            {reportSubmitted ? (
              <Typography variant="body1" color="success.main">
                Thank you for your feedback! Your report has been submitted.
              </Typography>
            ) : (
              <Button
                variant="outlined"
                color="secondary"
                startIcon={<FlagIcon />}
                onClick={handleReportUrl}
              >
                Report {isPhishing ? 'False Positive' : 'Missed Phishing URL'}
              </Button>
            )}
            
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Your feedback helps improve our detection model.
            </Typography>
          </Box>
        </Paper>

        <Box sx={{ mt: 4, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            For educational purposes only. Always exercise caution when visiting websites.
          </Typography>
        </Box>
      </Box>
    </Container>
  )
}

export default Results