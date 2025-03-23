document.addEventListener('DOMContentLoaded', async () => {
  // DOM elements
  const analysisResultElem = document.getElementById('analysis-result')
  const currentUrlElem = document.getElementById('current-url')
  const analyzeBtn = document.getElementById('analyze-btn')
  const reportBtn = document.getElementById('report-btn')
  const settingsBtn = document.getElementById('settings-btn')
  const settingsPanel = document.getElementById('settings-panel')
  const saveSettingsBtn = document.getElementById('save-settings')
  const cancelSettingsBtn = document.getElementById('cancel-settings')
  const realTimeScanningToggle = document.getElementById('real-time-scanning')
  const notificationLevelSelect = document.getElementById('notification-level')
  const redirectThresholdSlider = document.getElementById('redirect-threshold')
  const thresholdValueDisplay = document.getElementById('threshold-value')
  const chatRedirectDialog = document.getElementById('chat-redirect-dialog')
  const redirectYesBtn = document.getElementById('redirect-yes')
  const redirectNoBtn = document.getElementById('redirect-no')

  // Get the current tab URL
  const getCurrentTabUrl = async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    return tabs[0].url
  }

  // Format the analysis result display
  const formatAnalysisResult = (result) => {
    let statusClass = ''
    let statusIconHtml = ''
    
    if (result.status === 'Warning') {
      statusClass = 'result-warning'
      statusIconHtml = `<div class="status-icon"><span style="color: white; font-weight: bold;">✕</span></div>`
    } else if (result.status === 'Safe') {
      statusClass = 'result-safe'
      statusIconHtml = `<div class="status-icon"><span style="color: white; font-weight: bold;">✓</span></div>`
    } else {
      statusClass = 'result-none'
      statusIconHtml = `<div class="status-icon"><span style="color: white; font-weight: bold;">😊</span></div>`
    }
    
    return `
      <div class="analysis-result ${statusClass}">
        ${statusIconHtml}
        <div class="status-text">
          <span class="status-label">${result.status}</span>
          <span class="status-score">${result.score}/100</span>
        </div>
      </div>
    `
  }

  // Update UI with analysis result
  const updateAnalysisUI = async () => {
    try {
      // Get last analysis result from storage
      const lastAnalysis = await new Promise(resolve => {
        chrome.runtime.sendMessage(
          { action: 'getLastAnalysis' },
          response => resolve(response)
        )
      })
      
      if (!lastAnalysis) {
        // If no previous analysis, analyze the current URL
        const currentUrl = await getCurrentTabUrl()
        currentUrlElem.textContent = currentUrl
        
        if (currentUrl && currentUrl.startsWith('http')) {
          // Send message to background script to analyze the URL
          const result = await new Promise(resolve => {
            chrome.runtime.sendMessage(
              { action: 'analyzeUrl', url: currentUrl },
              response => resolve(response)
            )
          })
          
          analysisResultElem.innerHTML = formatAnalysisResult(result)
          
          // Show the chat redirect dialog if score is above threshold
          const settings = await chrome.storage.local.get('redirectThreshold')
          if (result.score >= (settings.redirectThreshold || 30)) {
            chatRedirectDialog.classList.remove('hidden')
          }
        } else {
          analysisResultElem.innerHTML = formatAnalysisResult({
            status: 'None',
            score: 0
          })
        }
      } else {
        // Display the last analysis result
        currentUrlElem.textContent = lastAnalysis.url
        analysisResultElem.innerHTML = formatAnalysisResult(lastAnalysis.result)
      }
    } catch (error) {
      console.error('Error updating UI:', error)
      analysisResultElem.innerHTML = 'An error occurred during analysis.'
    }
  }

  // Load settings into UI
  const loadSettings = async () => {
    const settings = await chrome.storage.local.get([
      'enableRealTimeScanning',
      'notificationLevel',
      'redirectThreshold'
    ])
    
    realTimeScanningToggle.checked = settings.enableRealTimeScanning !== false
    
    if (settings.notificationLevel) {
      notificationLevelSelect.value = settings.notificationLevel
    }
    
    if (settings.redirectThreshold !== undefined) {
      redirectThresholdSlider.value = settings.redirectThreshold
      thresholdValueDisplay.textContent = settings.redirectThreshold
    }
  }

  // Save settings
  const saveSettings = async () => {
    const settings = {
      enableRealTimeScanning: realTimeScanningToggle.checked,
      notificationLevel: notificationLevelSelect.value,
      redirectThreshold: parseInt(redirectThresholdSlider.value, 10)
    }
    
    await chrome.storage.local.set(settings)
    settingsPanel.classList.add('hidden')
  }

  // Initialize UI
  await updateAnalysisUI()
  await loadSettings()

  // Event listeners
  analyzeBtn.addEventListener('click', async () => {
    const currentUrl = await getCurrentTabUrl()
    if (currentUrl && currentUrl.startsWith('http')) {
      // Re-analyze the current URL
      const result = await new Promise(resolve => {
        chrome.runtime.sendMessage(
          { action: 'analyzeUrl', url: currentUrl },
          response => resolve(response)
        )
      })
      
      analysisResultElem.innerHTML = formatAnalysisResult(result)
      
      // Check if deep analysis is needed
      const settings = await chrome.storage.local.get('redirectThreshold')
      if (result.score >= (settings.redirectThreshold || 30)) {
        chatRedirectDialog.classList.remove('hidden')
      }
    }
  })

  reportBtn.addEventListener('click', async () => {
    const currentUrl = await getCurrentTabUrl()
    // False positive reporting mechanism 
    alert(`False positive reported for: ${currentUrl}`)
  })

  settingsBtn.addEventListener('click', () => {
    settingsPanel.classList.remove('hidden')
  })

  saveSettingsBtn.addEventListener('click', saveSettings)

  cancelSettingsBtn.addEventListener('click', () => {
    loadSettings(); // Reset any changes
    settingsPanel.classList.add('hidden')
  })

  redirectThresholdSlider.addEventListener('input', () => {
    thresholdValueDisplay.textContent = redirectThresholdSlider.value
  })

  redirectYesBtn.addEventListener('click', async () => {
    const currentUrl = await getCurrentTabUrl()
    // Redirect to chatbot with the URL
    const chatbotUrl = `https://chatbot-url.com?url=${encodeURIComponent(currentUrl)}`
    chrome.tabs.create({ url: chatbotUrl })
    chatRedirectDialog.classList.add('hidden')
  })

  redirectNoBtn.addEventListener('click', () => {
    chatRedirectDialog.classList.add('hidden')
  })
})