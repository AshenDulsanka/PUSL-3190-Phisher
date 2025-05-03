import { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Container, Box, Typography, Paper, Grid, Button,
  LinearProgress, Chip, Divider, List, ListItem,
  ListItemIcon, ListItemText, Alert, Card, CardContent
} from '@mui/material'
import SecurityIcon from '@mui/icons-material/Security'
import ArrowBackIcon from '@mui/icons-material/ArrowBack'
import CheckIcon from '@mui/icons-material/Check'
import CloseIcon from '@mui/icons-material/Close'
import WarningIcon from '@mui/icons-material/Warning'
import DangerousIcon from '@mui/icons-material/Dangerous'
import VerifiedIcon from '@mui/icons-material/Verified'
import FlagIcon from '@mui/icons-material/Flag'
import HelpOutlineIcon from '@mui/icons-material/HelpOutline'
import urlAnalysisService from '../services/urlAnalysisService'

const ResultsComp = () => {
  const [result, setResult] = useState(null)
  const [reportSubmitted, setReportSubmitted] = useState(false)
  const [visibleFeatures, setVisibleFeatures] = useState({})
  const location = useLocation()
  const navigate = useNavigate()

  useEffect(() => {
    if (!location.state?.result) {
      navigate('/')
      return
    }
    
    setResult(location.state.result)
    
    console.log('Features received:', location.state.result.features)
    
    // process features
    const significantFeatures = {}
    const result = location.state.result
    const threatScore = result.threatScore
    
    // always add baseline features for high-risk URLs
    if (threatScore > 50) {
      significantFeatures.suspiciousURL = true
    }
    
    // add any detected features from the result
    if (result.features) {
      Object.entries(result.features).forEach(([key, value]) => {
        // convert string values of "1" to true
        if (value === "1") value = true
        
        // convert string values of "0" to false
        if (value === "0") value = false
        
        // only include true boolean values or numbers > 0
        if ((typeof value === 'boolean' && value) || 
            (typeof value === 'number' && value > 0)) {
          significantFeatures[key] = value
        }
      })
    }
    
    // ensure we have at least some features for high-risk URLs
    if (Object.keys(significantFeatures).length === 0) {
      if (threatScore > 50) {
        significantFeatures.potentialPhishing = true
        significantFeatures.suspiciousDomain = true
      } else if (threatScore > 30) {
        significantFeatures.suspiciousURL = true
      }
    }
    
    setVisibleFeatures(significantFeatures)
    console.log('Significant features after processing:', significantFeatures)
  }, [location, navigate])

  const handleReportUrl = async () => {
    try {
      await urlAnalysisService.reportUrl({
        url: result.url,
        reportType: result.threatScore > 50 ? 'false_positive' : 'false_negative',
      })
      setReportSubmitted(true)
    } catch (error) {
      console.error('Error reporting URL:', error)
    }
  }
  
  // feature explanations
  const featureExplanations = {
    usingIP: 'Uses IP address instead of domain name',
    urlLength: 'Unusually long URL',
    hasAtSymbol: 'Contains @ symbol in URL',
    hasDash: 'Contains dashes in domain name',
    numSubdomains: 'Multiple subdomains',
    hasHTTPS: 'Secure HTTPS connection',
    domainAge: 'Recently registered domain',
    hasIframe: 'Contains hidden iframe elements',
    hasPopup: 'Uses popup windows',
    disablesRightClick: 'Prevents right-click',
    hasSpecialChars: 'Unusual special characters',
    isTyposquatting: 'Attempts to mimic a popular website',
    hasSuspiciousRedirect: 'Contains suspicious redirects',
    externalScripts: 'Loads scripts from external domains',
    suspiciousURL: 'URL structure has suspicious patterns',
    potentialPhishing: 'Contains characteristics of phishing URLs',
    suspiciousDomain: 'Domain name has suspicious characteristics'
  }
  
  // security tips
  const securityTips = [
    {
      title: "Check the URL carefully",
      description: "Verify that the domain name is spelled correctly. Phishers often use similar-looking domains."
    },
    {
      title: "Look for HTTPS",
      description: "Secure websites use HTTPS and show a padlock icon in the address bar."
    },
    {
      title: "Be cautious of urgency",
      description: "Phishing attempts often create false urgency to make you act without thinking."
    },
    {
      title: "Hover before clicking",
      description: "Hover over links to see where they actually lead before clicking."
    },
    {
      title: "Check for poor design",
      description: "Legitimate sites typically have professional design and proper grammar."
    },
    {
      title: "Don't share personal information",
      description: "Be very cautious about providing personal or financial information online."
    }
  ]

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
    threatScore,
    details,
  } = result
  
  // determine risk level based on new thresholds
  const isPhishing = threatScore > 50
  const isSuspicious = threatScore > 30 && threatScore <= 50

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Button 
        startIcon={<ArrowBackIcon />} 
        onClick={() => navigate('/')}
        sx={{ mb: 3 }}
      >
        Back to Analyzer
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
            color={isPhishing ? 'error' : isSuspicious ? 'warning' : 'success'} 
            sx={{ fontSize: 40, mr: 2 }} 
          />
          <Typography variant="h4" component="h1">
            URL Analysis Results
          </Typography>
        </Box>

        <Alert 
          severity={isPhishing ? 'error' : isSuspicious ? 'warning' : 'success'}
          icon={isPhishing ? <DangerousIcon /> : isSuspicious ? <WarningIcon /> : <VerifiedIcon />}
          sx={{ mb: 4, py: 2 }}
        >
          <Typography variant="h6">
            {isPhishing 
              ? 'Warning: This URL appears to be a phishing attempt!' 
              : isSuspicious 
                ? 'Caution: This URL has suspicious characteristics.'
                : 'This URL appears to be legitimate.'}
          </Typography>
        </Alert>

        <Box sx={{ mb: 4 }}>
          <Typography variant="subtitle1" gutterBottom>
            Analyzed URL:
          </Typography>
          <Chip 
            label={url} 
            variant="outlined" 
            sx={{ 
              maxWidth: '100%', 
              overflow: 'hidden', 
              fontSize: '1rem',
              py: 2.5,
              px: 1
            }} 
          />
        </Box>

        <Typography variant="h6" gutterBottom sx={{ mb: 2 }}>
          Risk Score: <Chip 
            label={`${threatScore}/100`} 
            color={isPhishing ? 'error' : isSuspicious ? 'warning' : 'success'} 
            sx={{ ml: 1 }} 
          />
        </Typography>

        {/* analysis Details */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            Analysis Details
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3 }}>
            {details || (isPhishing 
              ? 'Our AI model has detected multiple high-risk characteristics in this URL that strongly indicate a phishing attempt.'
              : isSuspicious
                ? 'Our analysis found some suspicious patterns in this URL. While not definitively malicious, caution is advised.'
                : 'Our analysis did not detect suspicious patterns typically associated with phishing attempts.'
            )}
          </Typography>
        </Box>

        {/* risk Factors */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            Detected Risk Factors
          </Typography>
          
          {Object.keys(visibleFeatures).length > 0 ? (
            <List dense>
              {Object.entries(visibleFeatures).map(([key, value]) => (
                <ListItem key={key} sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    {typeof value === 'boolean' ? (
                      key === 'hasHTTPS' ? (
                        value ? 
                          <CheckIcon color="success" /> : 
                          <CloseIcon color="error" />
                      ) : (
                        value ? 
                          <CheckIcon color="error" /> : 
                          <CloseIcon color="success" />
                      )
                    ) : (
                      <HelpOutlineIcon color="warning" />
                    )}
                  </ListItemIcon>
                  <ListItemText 
                    // update display text for hasHTTPS to show correct meaning based on value
                    primary={key === 'hasHTTPS' && !value ? 
                      'Missing secure HTTPS connection' : 
                      featureExplanations[key] || key}
                    secondary={typeof value === 'number' ? `Value: ${value}` : null}
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Typography variant="body1" color="text.secondary">
              {threatScore > 30 ? 
                "Risk factors information is limited. The overall score is based on combined pattern analysis." : 
                "No significant risk factors detected."
              }
            </Typography>
          )}
        </Box>

        <Divider sx={{ my: 4 }} />

        {/* user education */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h5" gutterBottom sx={{ mb: 3 }}>
            How to Protect Yourself from Phishing
          </Typography>
          
          <Grid container spacing={3} justifyContent="center">
            {securityTips.map((tip, index) => (
              <Grid item xs={12} sm={6} md={4} key={index}>
                <Card 
                  variant="outlined" 
                  sx={{ 
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column'
                  }}
                >
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                      {tip.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {tip.description}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>

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
    </Container>
  )
}

export default ResultsComp