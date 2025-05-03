import { useState, useEffect } from 'react'
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip
} from '@mui/material'

const Detections = () => {
  const [phishingURLs, setPhishingURLs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(10)
  
  useEffect(() => {
    const fetchDetections = async () => {
      try {
        setLoading(true)
        const token = localStorage.getItem('adminToken')
        if (!token) throw new Error('Authentication required')
        
        const response = await fetch('/api/url/admin/phishing-urls', {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        if (!response.ok) throw new Error('Failed to fetch phishing URLs')
        const data = await response.json()
        
        setPhishingURLs(data)
      } catch (err) {
        console.error('Detections error:', err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    
    fetchDetections()
  }, [])
  
  const handleChangePage = (event, newPage) => {
    setPage(newPage)
  }
  
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0)
  }
  
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}>
        <CircularProgress />
      </Box>
    )
  }
  
  if (error) {
    return (
      <Box sx={{ mt: 3 }}>
        <Typography variant="h6" color="error" align="center">
          {error}
        </Typography>
      </Box>
    )
  }
  
  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold', textAlign: 'center' }}>
        Phishing Detections
      </Typography>
      
      <Paper sx={{ width: '100%', overflow: 'hidden', borderRadius: 2 }}>
        <TableContainer>
          <Table stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 'bold' }}>URL</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Detection Time</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Score</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Status</TableCell>
                <TableCell sx={{ fontWeight: 'bold' }}>Source</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {phishingURLs
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((url) => (
                  <TableRow hover key={url.id}>
                    <TableCell sx={{ 
                      maxWidth: 300, 
                      overflow: 'hidden', 
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    }}>
                      {url.url}
                    </TableCell>
                    <TableCell>
                      {new Date(url.createdAt).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={url.suspiciousScore}
                        color={getScoreColor(url.suspiciousScore)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {url.isVerified ? (
                        <Chip label="Verified" color="success" size="small" />
                      ) : (
                        <Chip label="Unverified" color="default" size="small" />
                      )}
                    </TableCell>
                    <TableCell>
                      {url.detectionSource || 'System'}
                    </TableCell>
                  </TableRow>
                ))}
                
              {phishingURLs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography sx={{ py: 2 }}>
                      No phishing URLs detected
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          rowsPerPageOptions={[10, 25]}
          component="div"
          count={phishingURLs.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>
    </Box>
  )
}

// helper function to determine chip color based on score
const getScoreColor = (score) => {
  if (score >= 50) return 'error'
  if (score >= 30) return 'warning'
  return 'success'
}

export default Detections