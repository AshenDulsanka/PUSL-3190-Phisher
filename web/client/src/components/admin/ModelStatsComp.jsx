import { useState, useEffect } from 'react'
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  CardActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  FormControlLabel,
  Switch,
  IconButton,
  Alert
} from '@mui/material'
import MemoryIcon from '@mui/icons-material/Memory'
import EditIcon from '@mui/icons-material/Edit'
import SaveIcon from '@mui/icons-material/Save'
import CloseIcon from '@mui/icons-material/Close'

const ModelStatsComp = () => {
  const [models, setModels] = useState([])
  const [evaluations, setEvaluations] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(10)
  const [openDialog, setOpenDialog] = useState(false)
  const [selectedModel, setSelectedModel] = useState(null)
  const [formData, setFormData] = useState({
    accuracy: '',
    precision: '',
    recall: '',
    f1Score: '',
    areaUnderROC: '',
    feedbackIncorporated: false
  })
  const [success, setSuccess] = useState(null)

  useEffect(() => {
    const fetchModelData = async () => {
      try {
        setLoading(true)
        const token = localStorage.getItem('adminToken')
        if (!token) throw new Error('Authentication required')

        // fetch models
        const modelsResponse = await fetch('/api/url/admin/models', {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        if (!modelsResponse.ok) throw new Error('Failed to fetch models')
        const modelsData = await modelsResponse.json()
        
        setModels(modelsData)
        
        // fetch evaluation data for each model
        const evalData = {}
        for (const model of modelsData) {
          const evalResponse = await fetch(`/api/url/admin/model/${model.id}/evaluations`, {
            headers: { Authorization: `Bearer ${token}` }
          })
          
          if (evalResponse.ok) {
            const modelEvals = await evalResponse.json()
            evalData[model.id] = modelEvals
          }
        }
        
        setEvaluations(evalData)
      } catch (err) {
        console.error('Model stats data error:', err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    
    fetchModelData()
  }, [success])
  
  const handleChangePage = (event, newPage) => {
    setPage(newPage)
  }
  
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0);
  }
  
  const handleOpenDialog = (model) => {
    setSelectedModel(model)
    setFormData({
      accuracy: model.accuracy || '',
      precision: model.precision || '',
      recall: model.recall || '',
      f1Score: model.f1Score || '',
      areaUnderROC: model.areaUnderROC || '',
      feedbackIncorporated: model.feedbackIncorporated || false
    })
    setOpenDialog(true)
  }
  
  const handleCloseDialog = () => {
    setOpenDialog(false)
    setSelectedModel(null)
  }
  
  const handleFormChange = (e) => {
    const { name, value, type, checked } = e.target
    setFormData({ 
      ...formData, 
      [name]: type === 'checkbox' ? checked : value 
    })
  }
  
  const handleSubmit = async () => {
    try {
      const token = localStorage.getItem('adminToken')
      if (!token) throw new Error('Authentication required')
      
      const response = await fetch(`/api/url/admin/model/${selectedModel.id}/update`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          accuracy: formData.accuracy ? parseFloat(formData.accuracy) : null,
          precision: formData.precision ? parseFloat(formData.precision) : null,
          recall: formData.recall ? parseFloat(formData.recall) : null,
          f1Score: formData.f1Score ? parseFloat(formData.f1Score) : null,
          areaUnderROC: formData.areaUnderROC ? parseFloat(formData.areaUnderROC) : null,
          feedbackIncorporated: formData.feedbackIncorporated
        })
      })
      
      if (!response.ok) throw new Error('Failed to update model')
      
      setSuccess(`Model "${selectedModel.name}" updated successfully`)
      setTimeout(() => setSuccess(null), 3000)
      handleCloseDialog()
    } catch (err) {
      console.error('Model update error:', err)
      setError(err.message)
    }
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
        ML Models
      </Typography>
      
      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          {success}
        </Alert>
      )}
      
      {/* models overview */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {models.map((model) => (
          <Grid item xs={12} md={6} key={model.id}>
            <Card sx={{ borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Box sx={{ 
                  backgroundColor: '#3f83f820', 
                  borderRadius: '50%', 
                  width: 40, 
                  height: 40,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  mr: 2
                }}>
                  <MemoryIcon sx={{ color: '#3f83f8' }} />
                </Box>
                <Box sx={{ flexGrow: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h6" sx={{ fontWeight: 'bold', mr: 1 }}>
                      {model.name}
                    </Typography>
                    <Chip 
                      label={model.feedbackIncorporated ? "Continuous Learning" : "Static"} 
                      color={model.feedbackIncorporated ? "success" : "default"}
                      size="small"
                      sx={{ height: 24 }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {model.type} / v{model.version}
                  </Typography>
                </Box>
              </Box>
              
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={6} sm={4} md={2.4}>
                  <Typography variant="body2" color="text.secondary">Accuracy</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                    {model.accuracy ? `${(model.accuracy * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={4} md={2.4}>
                  <Typography variant="body2" color="text.secondary">Precision</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                    {model.precision ? `${(model.precision * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={4} md={2.4}>
                  <Typography variant="body2" color="text.secondary">Recall</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                    {model.recall ? `${(model.recall * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={4} md={2.4}>
                  <Typography variant="body2" color="text.secondary">F1 Score</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                    {model.f1Score ? `${(model.f1Score * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={4} md={2.4}>
                  <Typography variant="body2" color="text.secondary">Area Under ROC</Typography>
                  <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                    {model.areaUnderROC ? `${(model.areaUnderROC * 100).toFixed(1)}%` : 'N/A'}
                  </Typography>
                </Grid>
              </Grid>
              
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Trained on {new Date(model.trainedAt).toLocaleDateString()}
                </Typography>
                {model.lastUpdated && (
                  <Typography variant="body2" color="text.secondary">
                    Last updated {new Date(model.lastUpdated).toLocaleDateString()}
                  </Typography>
                )}
              </Box>
            </CardContent>
              <CardActions sx={{ justifyContent: 'flex-end', p: 2 }}>
                <Button
                  startIcon={<EditIcon />}
                  variant="outlined"
                  size="small"
                  onClick={() => handleOpenDialog(model)}
                >
                  Edit Metrics
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>
      
      {/* recent evaluations */}
      <Paper sx={{ p: 3, borderRadius: 2 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>Recent Model Evaluations</Typography>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Model</TableCell>
                <TableCell>URL</TableCell>
                <TableCell>Score</TableCell>
                <TableCell>Actual Label</TableCell>
                <TableCell>Time</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {models.flatMap(model => 
                (evaluations[model.id] || []).map((evaluation, index) => (
                  <TableRow key={`${model.id}-${index}`}>
                    <TableCell>{model.name}</TableCell>
                    <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {evaluation.url?.url || 'Unknown URL'}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={`${(evaluation.predictedScore * 100).toFixed(0)}%`}
                        color={evaluation.predictedScore > 0.5 ? "error" : "success"}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {evaluation.actualLabel === null ? 'Unknown' : 
                       evaluation.actualLabel ? 'Phishing' : 'Legitimate'}
                    </TableCell>
                    <TableCell>
                      {new Date(evaluation.evaluatedAt).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              ).slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)}
              
              {Object.keys(evaluations).length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography sx={{ py: 2 }}>
                      No evaluation data available
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
          count={models.flatMap(model => evaluations[model.id] || []).length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>
      
      {/* edit model dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>
          Edit Model Metrics
          <IconButton
            aria-label="close"
            onClick={handleCloseDialog}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 'bold' }}>
            {selectedModel?.name}
          </Typography>
          
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Accuracy"
                name="accuracy"
                type="number"
                fullWidth
                value={formData.accuracy}
                onChange={handleFormChange}
                inputProps={{ min: 0, max: 1, step: 0.01 }}
                helperText="Value between 0 and 1"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Precision"
                name="precision"
                type="number"
                fullWidth
                value={formData.precision}
                onChange={handleFormChange}
                inputProps={{ min: 0, max: 1, step: 0.01 }}
                helperText="Value between 0 and 1"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Recall"
                name="recall"
                type="number"
                fullWidth
                value={formData.recall}
                onChange={handleFormChange}
                inputProps={{ min: 0, max: 1, step: 0.01 }}
                helperText="Value between 0 and 1"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="F1 Score"
                name="f1Score"
                type="number"
                fullWidth
                value={formData.f1Score}
                onChange={handleFormChange}
                inputProps={{ min: 0, max: 1, step: 0.01 }}
                helperText="Value between 0 and 1"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Area Under ROC"
                name="areaUnderROC"
                type="number"
                fullWidth
                value={formData.areaUnderROC}
                onChange={handleFormChange}
                inputProps={{ min: 0, max: 1, step: 0.01 }}
                helperText="Value between 0 and 1"
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch 
                    checked={formData.feedbackIncorporated}
                    onChange={handleFormChange}
                    name="feedbackIncorporated"
                  />
                }
                label="Enable continuous learning from feedback"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button 
            startIcon={<SaveIcon />}
            variant="contained" 
            onClick={handleSubmit}
          >
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default ModelStatsComp