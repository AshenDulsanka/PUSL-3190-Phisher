import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import Home from './pages/Home'
import Results from './pages/Results'
import NotFound from './pages/NotFound'
import './App.css'

// Custom theme
const theme = createTheme({
  palette: {
    primary: {
      main: '#2BBE89', 
    },
    secondary: {
      main: '#FF5722', 
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
          <Route path="/results" element={<Results />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Router>
    </ThemeProvider>
  )
}

export default App