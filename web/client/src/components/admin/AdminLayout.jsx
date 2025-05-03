import { useState, useEffect } from 'react'
import { Outlet, useNavigate, useLocation, Link } from 'react-router-dom'
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  Avatar,
  Menu,
  MenuItem,
  Button,
  Container,
  IconButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
  useTheme
} from '@mui/material'
import DashboardIcon from '@mui/icons-material/Dashboard'
import WarningIcon from '@mui/icons-material/Warning'
import LogoutIcon from '@mui/icons-material/Logout'
import AssessmentIcon from '@mui/icons-material/Assessment'
import ListAltIcon from '@mui/icons-material/ListAlt'

const AdminLayout = () => {
  const [anchorEl, setAnchorEl] = useState(null)
  const navigate = useNavigate()
  const location = useLocation()
  const theme = useTheme()
  
  useEffect(() => {
    const token = localStorage.getItem('adminToken')
    if (!token) {
      navigate('/admin')
    }
  }, [navigate])
  
  const handleProfileMenuOpen = (event) => {
    setAnchorEl(event.currentTarget)
  }
  
  const handleMenuClose = () => {
    setAnchorEl(null)
  }
  
  const handleLogout = () => {
    localStorage.removeItem('adminToken')
    navigate('/admin')
    handleMenuClose()
  }
  
  const navItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/admin/dashboard' },
    { text: 'Detections', icon: <ListAltIcon />, path: '/admin/detections' },
    { text: 'Logs', icon: <WarningIcon />, path: '/admin/logs' },
    { text: 'Models', icon: <AssessmentIcon />, path: '/admin/models' }
  ]
  
  return (
    <Box sx={{ 
      display: 'flex', 
      flexDirection: 'column', 
      minHeight: '100vh',
      backgroundColor: theme.palette.background.default
    }}>
      <AppBar position="static" sx={{ backgroundColor: 'background.paper', boxShadow: 1 }}>
        <Toolbar>
          <Box sx={{ display: 'flex', alignItems: 'center', mr: 4 }}>
            <img 
              src="/logo-bg.png" 
              alt="Phisher Logo" 
              style={{ width: 36, height: 36, marginRight: '12px' }}
            />
            <Typography variant="h6" color="text.primary" sx={{ fontWeight: 'bold' }}>
              Phisher Admin
            </Typography>
          </Box>
          
          <Box sx={{ flexGrow: 1, display: 'flex' }}>
            {navItems.map((item) => (
              <Button
                key={item.text}
                component={Link}
                to={item.path}
                sx={{
                  color: location.pathname === item.path ? 'primary.main' : 'text.primary',
                  mx: 0.5,
                  py: 1,
                  fontWeight: location.pathname === item.path ? 'bold' : 'medium',
                  borderBottom: location.pathname === item.path ? 2 : 0,
                  borderColor: 'primary.main',
                  borderRadius: 0
                }}
                startIcon={item.icon}
              >
                {item.text}
              </Button>
            ))}
          </Box>
          
          <Box sx={{ flexGrow: 0 }}>
            <Tooltip title="Account settings">
              <IconButton onClick={handleProfileMenuOpen} sx={{ p: 0 }}>
                <Avatar sx={{ bgcolor: 'primary.main', width: 36, height: 36 }}>A</Avatar>
              </IconButton>
            </Tooltip>
            <Menu
              sx={{ mt: '45px' }}
              id="menu-appbar"
              anchorEl={anchorEl}
              anchorOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
              keepMounted
              transformOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
            >
              <MenuItem onClick={handleLogout}>
                <ListItemIcon>
                  <LogoutIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText>Logout</ListItemText>
              </MenuItem>
            </Menu>
          </Box>
        </Toolbar>
      </AppBar>
      
      <Container maxWidth="xl" sx={{ flexGrow: 1, py: 3 }}>
        <Outlet />
      </Container>
    </Box>
  )
}

export default AdminLayout