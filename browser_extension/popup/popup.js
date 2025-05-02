document.addEventListener('DOMContentLoaded', async function() {
  // get DOM elements
  const loadingSection = document.getElementById('loading')
  const resultSection = document.getElementById('result')
  const errorSection = document.getElementById('error')
  const urlText = document.getElementById('url-text')
  const scoreValue = document.getElementById('score-value')
  const gaugeValue = document.getElementById('gauge-value')
  const riskLevel = document.getElementById('risk-level')
  const detailsText = document.getElementById('details-text')
  const analyzeBtn = document.getElementById('analyze-btn')
  const reportBtn = document.getElementById('report-btn')
  const retryBtn = document.getElementById('retry-btn')
  const realTimeToggle = document.getElementById('real-time-toggle')
  const notificationLevel = document.getElementById('notification-level')
  const chatbotBtn = document.getElementById('chatbot-btn')
  
  // get the active tab URL
  let activeTab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    activeTab = tabs[0]
    
    // check if URL is valid for analysis
    if (!activeTab.url || !activeTab.url.startsWith('http')) {
      showError('This URL cannot be analyzed. Only HTTP/HTTPS URLs are supported.')
      return
    }
    
    urlText.textContent = activeTab.url
  } catch (error) {
    console.error('Error getting active tab:', error)
    showError('Unable to access the current tab information.')
    return
  }
  
  // load settings
  loadSettings()
  
  // check if we already have an analysis for this URL
  const storedAnalysis = await chrome.storage.local.get('lastAnalysis')
  if (storedAnalysis.lastAnalysis && 
      storedAnalysis.lastAnalysis.url === activeTab.url &&
      Date.now() - storedAnalysis.lastAnalysis.timestamp < 300000) { // 5 minutes
    // use stored analysis if it's recent
    displayAnalysisResult(storedAnalysis.lastAnalysis.result)
  } else {
    // request a new analysis
    analyzeCurrentUrl()
  }
  
  // event listeners
  analyzeBtn.addEventListener('click', analyzeCurrentUrl)
  retryBtn.addEventListener('click', analyzeCurrentUrl)
  
  reportBtn.addEventListener('click', function() {
    const reportUrl = 'https://phisher-chatbot.com/report?url=' + encodeURIComponent(activeTab.url)
    chrome.tabs.create({ url: reportUrl })
  })
  
  chatbotBtn.addEventListener('click', function() {
    const chatbotUrl = 'https://phisher-chatbot.com/?url=' + encodeURIComponent(activeTab.url)
    chrome.tabs.create({ url: chatbotUrl })
  })
  
  realTimeToggle.addEventListener('change', function() {
    chrome.storage.local.set({
      enableRealTimeScanning: realTimeToggle.checked
    })
  })
  
  notificationLevel.addEventListener('change', function() {
    chrome.storage.local.set({
      notificationLevel: notificationLevel.value
    })
  })
  
  // helper functions
  async function analyzeCurrentUrl() {
    showLoading()
    
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'analyzeUrl',
        url: activeTab.url
      })
      
      if (result.error) {
        throw new Error(result.error)
      }
      
      // Store the result
      chrome.storage.local.set({
        lastAnalysis: {
          url: activeTab.url,
          result: result,
          timestamp: Date.now()
        }
      })
      
      displayAnalysisResult(result)
    } catch (error) {
      console.error('Analysis error:', error)
      showError('Failed to analyze this URL. Please try again later.')
    }
  }
  
  function displayAnalysisResult(result) {
    // hide loading, show result
    loadingSection.style.display = 'none'
    resultSection.style.display = 'block'
    errorSection.style.display = 'none'
    
    // update score
    const score = result.score || 0
    scoreValue.textContent = score
    
    // update gauge (rotate needle based on score: 0-100 maps to 0-180 degrees)
    const rotation = (score / 100) * 180
    gaugeValue.style.transform = `rotate(${rotation}deg)`
    
    // update risk level
    let riskText, riskClass
    if (score >= 30) {
      riskText = 'Dangerous'
      riskClass = 'dangerous'
    } else if (score >= 20) {
      riskText = 'Suspicious'
      riskClass = 'suspicious'
    } else {
      riskText = 'Safe'
      riskClass = 'safe'
    }
    
    riskLevel.textContent = riskText
    riskLevel.className = 'risk-badge ' + riskClass
    
    // update details
    detailsText.textContent = result.details || 'No additional details available.'
    
    // if it's a dangerous URL, make the report button more prominent
    if (score >= 30) {
      reportBtn.classList.add('primary')
      reportBtn.classList.remove('secondary')
    } else {
      reportBtn.classList.add('secondary')
      reportBtn.classList.remove('primary')
    }
  }
  
  function showLoading() {
    loadingSection.style.display = 'flex'
    resultSection.style.display = 'none'
    errorSection.style.display = 'none'
  }
  
  function showError(message) {
    loadingSection.style.display = 'none'
    resultSection.style.display = 'none'
    errorSection.style.display = 'block'
    
    document.getElementById('error-message').textContent = message
  }
  
  async function loadSettings() {
    const settings = await chrome.storage.local.get([
      'enableRealTimeScanning',
      'notificationLevel'
    ])
    
    realTimeToggle.checked = settings.enableRealTimeScanning !== false
    notificationLevel.value = settings.notificationLevel || 'low'
  }
})