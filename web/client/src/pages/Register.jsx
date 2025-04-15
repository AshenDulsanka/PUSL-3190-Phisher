import { useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  Box, Container, Typography, TextField, Button, 
  Checkbox, FormControlLabel, InputAdornment, IconButton,
  Divider, Grid, Paper
} from '@mui/material'
import { Visibility, VisibilityOff } from '@mui/icons-material'
import ShieldIcon from '@mui/icons-material/Shield'
import FacebookIcon from '@mui/icons-material/Facebook'
import TwitterIcon from '@mui/icons-material/Twitter'
import AppleIcon from '@mui/icons-material/Apple'
import GoogleIcon from '@mui/icons-material/Google'

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    agreeToTerms: false,
  })

  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const handleChange = (e) => {
    const { name, value, checked } = e.target
    setFormData({
      ...formData,
      [name]: name === 'agreeToTerms' ? checked : value,
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    // form validation would go here
    if (formData.password !== formData.confirmPassword) {
      alert("Passwords don't match")
      return
    }
    
    // will implement actual API call later
    console.log('Form data submitted:', formData)
  }

  return (
    <Container maxWidth="sm">
      <Paper elevation={3} sx={{ mt: 8, p: 4, borderRadius: 2 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <ShieldIcon sx={{ color: 'primary.main', mr: 1, fontSize: '2rem' }} />
            <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
              Phisher
            </Typography>
          </Box>

          <Typography variant="h6" component="h2" sx={{ mb: 1, textAlign: 'center' }}>
            Join the fight against phishing! 🛡️
          </Typography>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3, textAlign: 'center' }}>
            Register now to detect and analyze malicious URLs with AI-powered security
          </Typography>

          <Box component="form" onSubmit={handleSubmit} sx={{ width: '100%' }}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="username"
              label="Username"
              name="username"
              autoComplete="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="Enter your username"
            />
            
            <TextField
              margin="normal"
              required
              fullWidth
              id="email"
              label="Email"
              name="email"
              autoComplete="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="Enter your email"
            />
            
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type={showPassword ? "text" : "password"}
              id="password"
              autoComplete="new-password"
              value={formData.password}
              onChange={handleChange}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            
            <TextField
              margin="normal"
              required
              fullWidth
              name="confirmPassword"
              label="Confirm Password"
              type={showConfirmPassword ? "text" : "password"}
              id="confirmPassword"
              autoComplete="new-password"
              value={formData.confirmPassword}
              onChange={handleChange}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle confirm password visibility"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      edge="end"
                    >
                      {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            
            <FormControlLabel
              control={
                <Checkbox 
                  checked={formData.agreeToTerms} 
                  onChange={handleChange} 
                  name="agreeToTerms" 
                  color="primary" 
                />
              }
              label={
                <Typography variant="body2">
                  I agree to <Link to="/privacy-policy">privacy policy</Link> & <Link to="/terms">terms</Link>
                </Typography>
              }
              sx={{ mt: 2 }}
            />
            
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ 
                mt: 2, 
                mb: 2,
                py: 1.5,
                bgcolor: 'primary.main',
                '&:hover': { bgcolor: '#24A579' }
              }}
              disabled={!formData.agreeToTerms}
            >
              Sign Up
            </Button>
            
            <Box sx={{ textAlign: 'center', mt: 2, mb: 2 }}>
              <Typography variant="body2" component="p">
                Already have an account? <Link to="/login" style={{ color: '#2BBE89', textDecoration: 'none' }}>Sign in instead</Link>
              </Typography>
            </Box>
            
            <Divider sx={{ my: 2 }}>or</Divider>
            
            <Grid container spacing={2}>
              <Grid item xs={3}>
                <Button 
                  fullWidth 
                  variant="outlined" 
                  sx={{ borderColor: '#E0E0E0', color: '#4267B2' }}
                >
                  <FacebookIcon />
                </Button>
              </Grid>
              <Grid item xs={3}>
                <Button 
                  fullWidth 
                  variant="outlined" 
                  sx={{ borderColor: '#E0E0E0', color: '#1DA1F2' }}
                >
                  <TwitterIcon />
                </Button>
              </Grid>
              <Grid item xs={3}>
                <Button 
                  fullWidth 
                  variant="outlined" 
                  sx={{ borderColor: '#E0E0E0', color: '#000000' }}
                >
                  <AppleIcon />
                </Button>
              </Grid>
              <Grid item xs={3}>
                <Button 
                  fullWidth 
                  variant="outlined" 
                  sx={{ borderColor: '#E0E0E0', color: '#DB4437' }}
                >
                  <GoogleIcon />
                </Button>
              </Grid>
            </Grid>
          </Box>
        </Box>
      </Paper>
    </Container>
  )
}

export default Register