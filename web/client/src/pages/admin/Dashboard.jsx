import React, { useState, useEffect } from 'react'
import {
  Box,
  Grid,
  Paper,
  Typography,
  CircularProgress,
  Card,
  CardContent,
  Divider
} from '@mui/material'
import LanguageIcon from '@mui/icons-material/Language'
import WarningIcon from '@mui/icons-material/Warning'
import ErrorIcon from '@mui/icons-material/Error'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js'

// register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
)

const AdminDashboard = () => {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [recentPhishing, setRecentPhishing] = useState([])

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const token = localStorage.getItem('adminToken')
        if (!token) throw new Error('Authentication required')

        // fetch stats
        const statsResponse = await fetch('/api/url/admin/stats', {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        if (!statsResponse.ok) throw new Error('Failed to fetch stats')
        const statsData = await statsResponse.json()
        
        // fetch recent phishing URLs
        const recentResponse = await fetch('/api/url/admin/recent-phishing', {
          headers: { Authorization: `Bearer ${token}` }
        })
        
        if (!recentResponse.ok) throw new Error('Failed to fetch recent data')
        const recentData = await recentResponse.json()
        
        setStats(statsData)
        setRecentPhishing(recentData)
      } catch (err) {
        console.error('Dashboard data error:', err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    
    fetchDashboardData()
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
  
  // mock data for chart
  const chartData = {
    labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
    datasets: [
      {
        label: 'URLs Scanned',
        data: [650, 590, 800, 810, 760, 830, 900],
        borderColor: '#3f83f8',
        backgroundColor: 'rgba(63, 131, 248, 0.1)',
        tension: 0.4
      },
      {
        label: 'Phishing URLs',
        data: [230, 190, 300, 410, 260, 230, 400],
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        tension: 0.4
      }
    ]
  }
  
  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: false
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        }
      },
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        }
      }
    }
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Admin Dashboard
      </Typography>
      
      {/* Stats summary cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard 
            title="Total URLs" 
            value={stats?.totalUrls || 0} 
            icon={<LanguageIcon />} 
            color="#3f83f8"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard 
            title="Phishing Detected" 
            value={stats?.phishingUrls || 0} 
            icon={<WarningIcon />} 
            color="#f59e0b"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard 
            title="False Positives" 
            value={stats?.falsePositives || 0} 
            icon={<ErrorIcon />} 
            color="#ef4444"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard 
            title="Accuracy" 
            value={`${stats?.accuracy || 0}%`} 
            icon={<CheckCircleIcon />} 
            color="#10b981"
          />
        </Grid>
      </Grid>
      
      {/* charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>Detection Trends</Typography>
            <Line data={chartData} options={chartOptions} height={80} />
          </Paper>
        </Grid>
      </Grid>
      
      {/* recent phishing URLs */}
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3, borderRadius: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>Recent Phishing Detections</Typography>
            <Box sx={{ width: '100%', overflow: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>URL</th>
                    <th style={{ textAlign: 'left', padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Detection Time</th>
                    <th style={{ textAlign: 'right', padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {recentPhishing.map((item, index) => (
                    <tr key={index}>
                      <td style={{ padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.05)', maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.url}
                      </td>
                      <td style={{ padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        {new Date(item.createdAt).toLocaleString()}
                      </td>
                      <td style={{ padding: '12px 8px', borderBottom: '1px solid rgba(255,255,255,0.05)', textAlign: 'right' }}>
                        <span style={{ 
                          backgroundColor: getScoreColor(item.suspiciousScore), 
                          padding: '4px 8px', 
                          borderRadius: '12px',
                          color: '#fff',
                          fontSize: '0.875rem'
                        }}>
                          {item.suspiciousScore}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  )
}

// helper component for stats cards
const StatCard = ({ title, value, icon, color }) => {
  return (
    <Card sx={{ borderRadius: 2, height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="subtitle1" color="text.secondary">
            {title}
          </Typography>
          <Box sx={{ 
            backgroundColor: `${color}20`, 
            borderRadius: '50%', 
            width: 40, 
            height: 40,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {React.cloneElement(icon, { sx: { color } })}
          </Box>
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  )
}

// helper function to get color based on score
const getScoreColor = (score) => {
  if (score >= 80) return '#ef4444'  // red
  if (score >= 50) return '#f59e0b'  // orange
  return '#10b981' // green
}

export default AdminDashboard