// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phisher extension installed')
    
    // Set default settings
    chrome.storage.local.set({
      enableRealTimeScanning: true,
      notificationLevel: 'medium', // low, medium, high
      redirectThreshold: 30
    })
  })
  
  // API endpoint for ML model
  const API_ENDPOINT = "https://test-api.com/analyze"
  
  // Function to extract features from URL
  function extractUrlFeatures(url) {
    try {
      // Parse the URL
      const urlObj = new URL(url)
      const domain = urlObj.hostname
      const fullUrl = url
      
      const features = {}

      // UsingIP - Check if IP address is used as domain
      features.UsingIP = /\d+\.\d+\.\d+\.\d+/.test(domain) ? 1 : 0
      
      // LongURL - Flag URLs that are suspiciously long
      features.LongURL = fullUrl.length > 75 ? 1 : 0
      
      // ShortURL - Check for URL shortening services
      const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'tiny.cc', 'shorte.st', 'go2l.ink']
      features.ShortURL = shorteners.some(shortener => domain.includes(shortener)) ? 1 : 0
      
      // Symbol@ - Check for @ symbol in URL
      features.SymbolAt = fullUrl.includes('@') ? 1 : 0
      
      // Redirecting// - Check for multiple forward slashes
      features.RedirectingSlashes = (fullUrl.match(/\/\//g) || []).length > 1 ? 1 : 0
      
      // PrefixSuffix- - Check for hyphens in domain
      features.PrefixSuffix = domain.includes('-') ? 1 : 0
      
      // SubDomains - Count subdomains (dots in domain)
      features.SubDomains = domain.split('.').length - 1
      
      // HTTPS - Check if URL uses HTTPS
      features.HTTPS = urlObj.protocol === 'https:' ? 1 : 0
      
      // DomainRegLen - Estimate domain age/registration length
      features.DomainRegLen = 0
      
      // NonStdPort - Check for non-standard port
      features.NonStdPort = urlObj.port && ![80, 443, ''].includes(urlObj.port) ? 1 : 0
      
      // HTTPSDomainURL - Check if 'https' appears in domain part
      features.HTTPSDomainURL = domain.includes('https') ? 1 : 0
      
      // AbnormalURL - Check for suspicious patterns
      const suspiciousTerms = ['login', 'signin', 'verify', 'account', 'security', 'update', 'confirm', 'payment']
      features.AbnormalURL = suspiciousTerms.some(term => fullUrl.toLowerCase().includes(term)) ? 1 : 0
      
      // InfoEmail - Check for email-related terms
      features.InfoEmail = ['mail', 'email', 'contact'].some(term => fullUrl.toLowerCase().includes(term)) ? 1 : 0
      
      // URL entropy (measure of randomness)
      features.URLEntropy = calculateEntropy(domain)
      
      // Domain length 
      features.DomainLength = domain.length
      
      // Special character ratio
      features.SpecialCharRatio = (fullUrl.match(/[^a-zA-Z0-9.]/g) || []).length / fullUrl.length
      
      return features
    } catch (error) {
      console.error('Error extracting features:', error)
      return {
        UsingIP: 0,
        LongURL: 0,
        ShortURL: 0,
        SymbolAt: 0,
        RedirectingSlashes: 0,
        PrefixSuffix: 0,
        SubDomains: 0,
        HTTPS: 0,
        DomainRegLen: 0,
        NonStdPort: 0,
        HTTPSDomainURL: 0,
        AbnormalURL: 0,
        InfoEmail: 0,
        URLEntropy: 0,
        DomainLength: 0,
        SpecialCharRatio: 0
      }
    }
  }

  // Helper function to calculate entropy (randomness) of URL
  function calculateEntropy(text) {
    if (!text) return 0;
    
    // Count character frequencies
    const charFreq = {};
    for (let i = 0; i < text.length; i++) {
      const char = text[i].toLowerCase();
      charFreq[char] = (charFreq[char] || 0) + 1;
    }
    
    // Calculate entropy
    let entropy = 0;
    const len = text.length;
    Object.values(charFreq).forEach(count => {
      const p = count / len;
      entropy -= p * Math.log2(p);
    });
    
    return entropy;
  }
  
  // Function to make prediction using the ML model via API
  async function analyzeSuspiciousUrl(url) {
    try {
      // For development/testing - simulate an API response
      if (process.env.NODE_ENV === 'development') {
        // Simulate different scores for demo purposes
        const score = url.includes('login') || url.includes('signin') ? 
          Math.floor(Math.random() * 70) + 30 : 
          Math.floor(Math.random() * 30)
        
        return {
          score: score,
          status: score > 60 ? 'Warning' : score > 20 ? 'Safe' : 'None',
          details: 'Simulated analysis for development'
        }
      }
      
      // Extract features
      const features = extractUrlFeatures(url)
      
      // Call the API for real analysis
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url, features })
      })
      
      if (!response.ok) {
        throw new Error('API request failed')
      }
      
      return await response.json()
    } catch (error) {
      console.error('Error analyzing URL:', error)
      return {
        score: 0,
        status: 'Error',
        details: 'Could not analyze URL'
      }
    }
  }
  
  // Listen for tab updates to check URLs
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Check if the tab has completed loading and has a URL
    if (changeInfo.status === 'complete' && tab.url) {
      // Skip browser internal pages
      if (!tab.url.startsWith('http')) return
      
      // Get settings
      const settings = await chrome.storage.local.get([
        'enableRealTimeScanning',
        'redirectThreshold'
      ])
      
      // Skip if real-time scanning is disabled
      if (!settings.enableRealTimeScanning) return
      
      const analysis = await analyzeSuspiciousUrl(tab.url)
      
      // Send analysis result to content script
      chrome.tabs.sendMessage(tabId, {
        action: 'analysisResult',
        data: analysis
      })
      
      // Update badge based on risk level
      if (analysis.score > 60) {
        chrome.action.setBadgeBackgroundColor({ color: '#FF5F5F' });
        chrome.action.setBadgeText({ text: '!' })
      } else if (analysis.score > 20) {
        chrome.action.setBadgeBackgroundColor({ color: '#75D7BE' });
        chrome.action.setBadgeText({ text: '✓' })
      } else {
        chrome.action.setBadgeText({ text: '' })
      }
      
      // Store the result for the popup to access
      chrome.storage.local.set({ lastAnalysis: {
        url: tab.url,
        result: analysis,
        timestamp: Date.now()
      }})
      
      // If score exceeds the redirect threshold, notify the user
      if (analysis.score >= settings.redirectThreshold) {
        chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          data: {
            score: analysis.score,
            url: tab.url
          }
        })
      }
    }
  })
  
  // Listen for messages from popup or content script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeUrl') {
      analyzeSuspiciousUrl(request.url)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ error: error.message }))
      return true
    }
    
    if (request.action === 'getLastAnalysis') {
      chrome.storage.local.get('lastAnalysis', (data) => {
        sendResponse(data.lastAnalysis || null)
      })
      return true
    }
  })