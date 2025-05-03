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
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Grid,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton
} from '@mui/material'
import RefreshIcon from '@mui/icons-material/Refresh'
import FilterAltIcon from '@mui/icons-material/FilterAlt'
import ClearIcon from '@mui/icons-material/Clear'
import CloseIcon from '@mui/icons-material/Close'

const SystemLogs = () => {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(10)
  const [filters, setFilters] = useState({
    component: '',
    logLevel: '',
    search: ''
  })
  
  // Add state for the metadata dialog
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false)
  const [selectedMetadata, setSelectedMetadata] = useState(null)
  
  const fetchLogs = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('adminToken')
      if (!token) throw new Error('Authentication required')
      
      // build query string from filters
      const queryParams = new URLSearchParams()
      if (filters.component) queryParams.append('component', filters.component)
      if (filters.logLevel) queryParams.append('logLevel', filters.logLevel)
      if (filters.search) queryParams.append('search', filters.search)
      
      const response = await fetch(`/api/url/admin/logs?${queryParams.toString()}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      
      if (!response.ok) throw new Error('Failed to fetch logs')
      const data = await response.json()
      setLogs(data)
    } catch (err) {
      console.error('System logs error:', err)
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }
  
  useEffect(() => {
    fetchLogs()
  }, [])
  
  const handleChangePage = (event, newPage) => {
    setPage(newPage)
  }
  
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0)
  }
  
  const handleFilterChange = (event) => {
    const { name, value } = event.target
    setFilters(prev => ({ ...prev, [name]: value }))
  }
  
  const applyFilters = () => {
    fetchLogs()
  }
  
  const clearFilters = () => {
    setFilters({
      component: '',
      logLevel: '',
      search: ''
    })
    fetchLogs()
  }
  
  const getLogLevelColor = (level) => {
    switch (level.toLowerCase()) {
      case 'error': return 'error'
      case 'warning': return 'warning'
      case 'info': return 'info'
      case 'debug': return 'default'
      default: return 'default'
    }
  }
  
  // Handle showing metadata in dialog
  const handleViewMetadata = (metadata) => {
    try {
      // Attempt to parse the metadata if it's a JSON string
      const parsedMetadata = typeof metadata === 'string' ? JSON.parse(metadata) : metadata;
      setSelectedMetadata(parsedMetadata);
    } catch {
      // If parsing fails, just use the original string
      setSelectedMetadata(metadata);
    }
    setMetadataDialogOpen(true);
  };
  
  // Handle closing metadata dialog
  const handleCloseMetadataDialog = () => {
    setMetadataDialogOpen(false);
    setSelectedMetadata(null);
  };
  
  if (loading && logs.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}>
        <CircularProgress />
      </Box>
    )
  }
  
  if (error && logs.length === 0) {
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
        System Logs
      </Typography>
      
      {/* filter controls */}
      <Box sx={{ 
        mb: 3, 
        p: 1.5,
        borderRadius: 2, 
        bgcolor: 'background.paper',
        display: 'flex',
        alignItems: 'center',
        gap: 1
      }}>
        <FormControl size="small" sx={{ width: 118 }}>
          <InputLabel id="level-filter-label">Log Level</InputLabel>
          <Select
            labelId="level-filter-label"
            id="level-filter"
            name="logLevel"
            value={filters.logLevel}
            onChange={handleFilterChange}
            label="Log Level"
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="info">Info</MenuItem>
            <MenuItem value="warning">Warning</MenuItem>
            <MenuItem value="error">Error</MenuItem>
            <MenuItem value="debug">Debug</MenuItem>
          </Select>
        </FormControl>
        
        <TextField
          size="small"
          name="search"
          placeholder="Search Messages"
          value={filters.search}
          onChange={handleFilterChange}
          sx={{ flex: 1 }}
          InputProps={{ sx: { bgcolor: 'background.default' } }}
        />
        
        <Button
          variant="contained"
          startIcon={<FilterAltIcon />}
          onClick={applyFilters}
          sx={{ height: 40 }}
        >
          FILTER
        </Button>
        
        <Button
          variant="outlined"
          startIcon={<ClearIcon />}
          onClick={clearFilters}
          sx={{ height: 40 }}
        >
          CLEAR
        </Button>
        
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={fetchLogs}
          sx={{ height: 40 }}
        >
          REFRESH
        </Button>
      </Box>
      
      {/* logs table - removed maxHeight to match other tables */}
      <Paper sx={{ width: '100%', overflow: 'hidden', borderRadius: 2 }}>
        <TableContainer>
          <Table stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Component</TableCell>
                <TableCell>Level</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Metadata</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {logs
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((log) => (
                  <TableRow hover key={log.id}>
                    <TableCell>
                      {new Date(log.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip label={log.component} size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={log.logLevel} 
                        color={getLogLevelColor(log.logLevel)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{log.message}</TableCell>
                    <TableCell>
                      {log.metadata ? (
                        <Button 
                          size="small" 
                          variant="outlined" 
                          onClick={() => handleViewMetadata(log.metadata)}
                        >
                          View
                        </Button>
                      ) : (
                        'N/A'
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                
              {logs.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography sx={{ py: 2 }}>
                      No logs found
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
          count={logs.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>
      
      {/* Metadata dialog */}
      <Dialog 
        open={metadataDialogOpen} 
        onClose={handleCloseMetadataDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Log Metadata
          <IconButton
            aria-label="close"
            onClick={handleCloseMetadataDialog}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedMetadata && (
            <Box sx={{ 
              backgroundColor: 'background.paper', 
              p: 2, 
              borderRadius: 1,
              fontFamily: 'monospace',
              whiteSpace: 'pre-wrap',
              overflowX: 'auto'
            }}>
              {typeof selectedMetadata === 'object' 
                ? JSON.stringify(selectedMetadata, null, 2)
                : selectedMetadata}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseMetadataDialog}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default SystemLogs