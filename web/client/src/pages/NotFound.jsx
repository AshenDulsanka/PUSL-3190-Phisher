import { Box, Button, Container, Typography } from '@mui/material'
import { Link } from 'react-router-dom'

const NotFound = () => {
  return (
    <Container>
      <Box sx={{ 
        mt: 8, 
        display: 'flex', 
        flexDirection: 'column', 
        alignItems: 'center',
        textAlign: 'center'
      }}>
        <Typography variant="h1">404</Typography>
        <Typography variant="h4" sx={{ mb: 4 }}>Page Not Found</Typography>
        <Typography variant="body1" sx={{ mb: 4 }}>
          The page you're looking for doesn't exist or has been moved.
        </Typography>
        <Button component={Link} to="/" variant="contained">
          Go Home
        </Button>
      </Box>
    </Container>
  )
}

export default NotFound