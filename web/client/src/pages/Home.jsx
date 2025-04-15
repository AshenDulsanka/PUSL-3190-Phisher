import { Box, Button, Container, Typography } from '@mui/material'
import { Link } from 'react-router-dom'
import ShieldIcon from '@mui/icons-material/Shield'

const Home = () => {
  return (
    <Container>
      <Box sx={{ 
        mt: 8, 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center',
        textAlign: 'center'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
          <ShieldIcon sx={{ color: 'primary.main', mr: 1, fontSize: '3rem' }} />
          <Typography variant="h3" component="h1" sx={{ fontWeight: 600 }}>
            Phisher
          </Typography>
        </Box>
        
        <Typography variant="h4" sx={{ mb: 4 }}>
          AI-Powered Phishing Detection System
        </Typography>
        
        <Typography variant="body1" sx={{ mb: 4, maxWidth: '600px' }}>
          Protect yourself and your organization from phishing attacks with our advanced AI detection system. 
          Analyze URLs in real-time and get detailed security reports.
        </Typography>
        
        <Box sx={{ mt: 2 }}>
          <Button 
            component={Link} 
            to="/register" 
            variant="contained" 
            size="large"
            sx={{ mr: 2 }}
          >
            Sign Up
          </Button>
          <Button 
            component={Link} 
            to="/login" 
            variant="outlined" 
            size="large"
          >
            Sign In
          </Button>
        </Box>
      </Box>
    </Container>
  )
}

export default Home