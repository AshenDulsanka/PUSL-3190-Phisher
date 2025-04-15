import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import Register from './pages/Register'
import Login from './pages/Login'
import Home from './pages/Home'
import NotFound from './pages/NotFound'
import './App.css'

// Custom theme
const theme = createTheme({
  palette: {
    primary: {
      main: '#2BBE89', // Green from your design
    },
    secondary: {
      main: '#FF5722', // Orange for warnings
    },
    background: {
      default: '#F5F5F5',
    },
  },
  typography: {
    fontFamily: "'Inter', 'Roboto', sans-serif",
  },
})

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Router>
    </ThemeProvider>
  )
}

export default App