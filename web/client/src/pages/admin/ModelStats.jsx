import { useState, useEffect } from 'react'
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip
} from '@mui/material'
import MemoryIcon from '@mui/icons-material/Memory'

const ModelStats = () => {
  const [models, setModels] = useState([])
  const [evaluations, setEvaluations] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

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
  }, [])
  
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
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        ML Models
      </Typography>
      
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
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                      {model.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {model.type} / v{model.version}
                    </Typography>
                  </Box>
                  <Chip 
                    label={model.feedbackIncorporated ? "Continuous Learning" : "Static"} 
                    color={model.feedbackIncorporated ? "success" : "default"}
                    size="small" 
                    sx={{ ml: 'auto' }} 
                  />
                </Box>
                
                <Grid container spacing={2} sx={{ mt: 1 }}>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" color="text.secondary">Accuracy</Typography>
                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                      {model.accuracy ? `${(model.accuracy * 100).toFixed(1)}%` : 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" color="text.secondary">Precision</Typography>
                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                      {model.precision ? `${(model.precision * 100).toFixed(1)}%` : 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" color="text.secondary">Recall</Typography>
                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                      {model.recall ? `${(model.recall * 100).toFixed(1)}%` : 'N/A'}
                    </Typography>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Typography variant="body2" color="text.secondary">F1 Score</Typography>
                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                      {model.f1Score ? `${(model.f1Score * 100).toFixed(1)}%` : 'N/A'}
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
            </Card>
          </Grid>
        ))}
      </Grid>
      
      {/* Recent evaluations */}
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
              {models.map(model => (
                (evaluations[model.id] || []).slice(0, 5).map((evaluation, index) => (
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
              ))}
              
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
      </Paper>
    </Box>
  )
}

export default ModelStats