import React, { useState, useEffect } from 'react'
import {
  Box,
  Grid,
  Paper,
  Typography,
  CircularProgress,
  Card,
  CardContent
} from '@mui/material'
import LanguageIcon from '@mui/icons-material/Language'
import WarningIcon from '@mui/icons-material/Warning'
import ErrorIcon from '@mui/icons-material/Error'
import ReportProblemIcon from '@mui/icons-material/ReportProblem'
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

// register chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
)

const DashboardComp = () => {
  const [stats, setStats] = useState(null)
  const [trendData, setTrendData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [, setError] = useState(null)

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true)
        const token = localStorage.getItem('adminToken')
        if (!token) throw new Error('Authentication required')
  
        // fetch general stats
        const statsResponse = await fetch(`/api/url/admin/stats`, {
          headers: { 
            Authorization: `Bearer ${token}`,
            'Cache-Control': 'no-cache, no-store, must-revalidate' 
          }
        })
        
        if (!statsResponse.ok) throw new Error('Failed to fetch stats')
        const statsData = await statsResponse.json()
        setStats(statsData)
        
        // fetch trend data for chart
        const trendsResponse = await fetch(`/api/url/admin/trends`, {
          headers: { 
            Authorization: `Bearer ${token}`,
            'Cache-Control': 'no-cache, no-store, must-revalidate' 
          }
        })
        
        if (!trendsResponse.ok) throw new Error('Failed to fetch trend data')
        const trendsData = await trendsResponse.json()
        setTrendData(trendsData)

      } catch (err) {
        console.error('Dashboard data error:', err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    
    fetchDashboardData()
  }, [])
  
  // create chart data from the API trend data instead of hardcoded values
  const chartData = React.useMemo(() => {
    if (!trendData || !trendData.labels || !trendData.urlsScanned || !trendData.phishingUrls) {
      return {
        labels: [],
        datasets: [
          {
            label: 'URLs Scanned',
            data: [],
            borderColor: '#3f83f8',
            backgroundColor: 'rgba(63, 131, 248, 0.1)',
            tension: 0.4
          },
          {
            label: 'Phishing URLs',
            data: [],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            tension: 0.4
          }
        ]
      }
    }
    
    return {
      labels: trendData.labels,
      datasets: [
        {
          label: 'URLs Scanned',
          data: trendData.urlsScanned,
          borderColor: '#3f83f8',
          backgroundColor: 'rgba(63, 131, 248, 0.1)',
          tension: 0.4
        },
        {
          label: 'Phishing URLs',
          data: trendData.phishingUrls,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.4
        }
      ]
    }
  }, [trendData])
  
  const chartOptions = {
    // Keep your existing options
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: false
      },
      tooltip: {
        mode: 'index',
        intersect: false
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
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold', textAlign: 'center' }}>
        Admin Dashboard
      </Typography>
      
      {/* stats summary cards */}
      <Grid container spacing={2} sx={{ mb: 4 }}>
        <Grid item xs={12} md={2.4}>
          <StatCard 
            title="Total URLs" 
            value={stats?.totalUrls || 0} 
            icon={<LanguageIcon />} 
            color="#3f83f8"
          />
        </Grid>
        <Grid item xs={12} md={2.4}>
          <StatCard 
            title="Phishing Detected" 
            value={stats?.phishingUrls || 0} 
            icon={<WarningIcon />} 
            color="#f59e0b"
          />
        </Grid>
        <Grid item xs={12} md={2.4}>
          <StatCard 
            title="False Positives" 
            value={stats?.falsePositives || 0} 
            icon={<ErrorIcon />} 
            color="#ef4444"
          />
        </Grid>
        <Grid item xs={12} md={2.4}>
          <StatCard 
            title="False Negatives" 
            value={stats?.falseNegatives || 0} 
            icon={<ReportProblemIcon />} 
            color="#9333ea"
          />
        </Grid>
        <Grid item xs={12} md={2.4}>
          <StatCard 
            title="Accuracy" 
            value={`${stats?.accuracy || 0}%`} 
            icon={<CheckCircleIcon />} 
            color="#10b981"
          />
        </Grid>
      </Grid>
      
      {/* detection trends chart */}
      <Paper sx={{ p: 4, borderRadius: 2, mb: 4 }}>
          <Typography variant="h6" sx={{ mb: 3, fontWeight: 'bold' }}>Detection Trends</Typography>
          <Box sx={{ height: 400 }}>
              {trendData ? (
              <Line data={chartData} options={chartOptions} />
              ) : (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <Typography variant="body1" color="text.secondary">
                  {loading ? 'Loading trend data...' : 'No trend data available'}
                  </Typography>
              </Box>
              )}
          </Box>
      </Paper>
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

export default DashboardComp