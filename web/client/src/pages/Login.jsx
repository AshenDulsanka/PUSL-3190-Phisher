import { useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  Box, Container, Typography, TextField, Button, 
  InputAdornment, IconButton, Divider, Grid, Paper
} from '@mui/material'
import { Visibility, VisibilityOff } from '@mui/icons-material'
import ShieldIcon from '@mui/icons-material/Shield'
import FacebookIcon from '@mui/icons-material/Facebook'
import TwitterIcon from '@mui/icons-material/Twitter'
import AppleIcon from '@mui/icons-material/Apple'
import GoogleIcon from '@mui/icons-material/Google'

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  })
  const [showPassword, setShowPassword] = useState(false)

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    console.log('Login data submitted:', formData)
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
            Welcome Back!
          </Typography>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3, textAlign: 'center' }}>
            Sign in to continue protecting against phishing attacks
          </Typography>

          <Box component="form" onSubmit={handleSubmit} sx={{ width: '100%' }}>
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
              autoComplete="current-password"
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
            
            <Box sx={{ textAlign: 'right', mt: 1 }}>
              <Link to="/forgot-password" style={{ color: '#2BBE89', textDecoration: 'none' }}>
                <Typography variant="body2">Forgot password?</Typography>
              </Link>
            </Box>
            
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ 
                mt: 3, 
                mb: 2,
                py: 1.5,
                bgcolor: 'primary.main',
                '&:hover': { bgcolor: '#24A579' }
              }}
            >
              Sign In
            </Button>
            
            <Box sx={{ textAlign: 'center', mt: 2, mb: 2 }}>
              <Typography variant="body2" component="p">
                Don't have an account? <Link to="/register" style={{ color: '#2BBE89', textDecoration: 'none' }}>Sign up</Link>
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

export default Login