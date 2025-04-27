// initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phisher extension installed')
  
  // set default settings
  chrome.storage.local.set({
    enableRealTimeScanning: true,
    notificationLevel: 'medium', // low, medium, high
    redirectThreshold: 30
  })
})

// API endpoint for ML model
const API_ENDPOINT = "http://localhost:8000/api/analyze-url"

// function to extract features from URL
function extractUrlFeatures(url) {
  try {
    // parse the URL
    const urlObj = new URL(url)
    const domain = urlObj.hostname
    const fullUrl = url
    
    const features = {}
    
    // url_length - actual URL length
    features.url_length = fullUrl.length
    
    // num_dots - count of dots in the URL
    features.num_dots = fullUrl.split('.').length - 1
    
    // num_special_chars - count of special characters
    features.num_special_chars = (fullUrl.match(/[^a-zA-Z0-9.]/g) || []).length
    
    // has_ip - check if IP address is used as domain
    features.has_ip = /\d+\.\d+\.\d+\.\d+/.test(domain) ? 1 : 0
    
    // has_at_symbol - check for @ symbol
    features.has_at_symbol = fullUrl.includes('@') ? 1 : 0
    
    // num_subdomains - count subdomains
    features.num_subdomains = domain.split('.').length - 1
    
    // has_https - check if URL uses HTTPS
    features.has_https = urlObj.protocol === 'https:' ? 1 : 0
    
    // has_hyphen - check for hyphens in domain
    features.has_hyphen = domain.includes('-') ? 1 : 0
    
    // is_shortened - check for URL shortening services
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
    features.is_shortened = shorteners.some(shortener => domain.includes(shortener)) ? 1 : 0
    
    // Keep some extra features for heuristic fallback
    features._redirecting_slashes = (fullUrl.match(/\/\//g) || []).length > 1 ? 1 : 0
    features._abnormal_url = ['login', 'signin', 'verify', 'account', 'security'].some(term => fullUrl.toLowerCase().includes(term)) ? 1 : 0
    features._url_entropy = calculateEntropy(domain)
    
    return features
  } catch (error) {
    console.error('Error extracting features:', error)
    return {
      url_length: 0,
      num_dots: 0,
      num_special_chars: 0,
      has_ip: 0,
      has_at_symbol: 0,
      num_subdomains: 0,
      has_https: 0,
      has_hyphen: 0,
      is_shortened: 0,
      // Fallback features
      _redirecting_slashes: 0,
      _abnormal_url: 0,
      _url_entropy: 0
    }
  }
}

// helper function to calculate entropy (randomness) of URL
function calculateEntropy(text) {
  if (!text) return 0;
  
  // count character frequencies
  const charFreq = {};
  for (let i = 0; i < text.length; i++) {
    const char = text[i].toLowerCase();
    charFreq[char] = (charFreq[char] || 0) + 1;
  }
  
  // calculate entropy
  let entropy = 0;
  const len = text.length;
  Object.values(charFreq).forEach(count => {
    const p = count / len;
    entropy -= p * Math.log2(p);
  });
  
  return entropy;
}

// function to make prediction using the ML model via API
async function analyzeSuspiciousUrl(url) {
  try {
    // extract features
    const features = extractUrlFeatures(url)

    // features debugging
    console.log('Extracted features:', features)
    
    // call the API for real analysis
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ 
        url: url, 
        client: 'browser_extension'
      })
    })
    
    if (!response.ok) {
      const errorText = await response.text()
      console.error('API Error:', errorText)
      throw new Error(`API request failed: ${response.status}`)
    }

    const data = await response.json()
    console.log('API response:', data)

    // verify threat_score exists
    if (data.threat_score === undefined) {
      console.error('API response missing threat_score')
      throw new Error('Invalid API response: missing threat_score')
    }
    
    return {
      score: data.threat_score || data.score || 0,
      is_phishing: data.is_phishing || false,
      status: data.is_phishing ? 'Warning' : 'Safe',
      details: data.details || 'URL analyzed successfully',
      confidence: data.probability || 0
    }
  } catch (error) {
    console.error('Error analyzing URL:', error)

    // fallback to simple heuristics if API fails
    const features = extractUrlFeatures(url)
    const heuristicScore = calculateHeuristicScore(features)

    return {
      score: heuristicScore,
      is_phishing: heuristicScore > 60,
      status: heuristicScore > 60 ? 'Warning' : heuristicScore > 30 ? 'Suspicious' : 'Safe',
      details: 'Analyzed using offline heuristics (API unavailable)',
      confidence: 0.5
    }
  }
}

// simple heuristic scoring as fallback when API is unavailable
function calculateHeuristicScore(features) {
  let score = 0
  
  // add points for each suspicious feature
  if (features.has_ip) score += 20
  if (features.url_length > 75) score += 10
  if (features.is_shortened) score += 15
  if (features.has_at_symbol) score += 20
  if (features._redirecting_slashes) score += 10
  if (features.has_hyphen) score += 10
  if (features.num_subdomains > 2) score += 10
  if (!features.has_https) score += 15
  if (features._abnormal_url) score += 15
  if (features._url_entropy > 4) score += 10
  
  // cap the score at 100
  return Math.min(score, 100)
}

// listen for tab updates to check URLs
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // check if the tab has completed loading and has a URL
  if (changeInfo.status === 'complete' && tab.url) {
    // skip browser internal pages
    if (!tab.url.startsWith('http')) return
    
    // get settings
    const settings = await chrome.storage.local.get([
      'enableRealTimeScanning',
      'notificationLevel',
      'redirectThreshold'
    ])
    
    // skip if real-time scanning is disabled
    if (!settings.enableRealTimeScanning) return
    
    try {
      const analysis = await analyzeSuspiciousUrl(tab.url)
      
      // send analysis result to content script
      chrome.tabs.sendMessage(tabId, {
        action: 'analysisResult',
        data: analysis
      }).catch(err => console.log('Error sending message to content script:', err))
      
      // update badge based on risk level
      if (analysis.score > 70) {
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' })
        chrome.action.setBadgeText({ text: '!' })
      } else if (analysis.score > 40) {
        chrome.action.setBadgeBackgroundColor({ color: '#FFA500' })
        chrome.action.setBadgeText({ text: '?' })
      } else {
        chrome.action.setBadgeBackgroundColor({ color: '#00C853' })
        chrome.action.setBadgeText({ text: '✓' })
      }
      
      // store the result for the popup to access
      chrome.storage.local.set({ 
        lastAnalysis: {
          url: tab.url,
          result: analysis,
          timestamp: Date.now()
        }
      })
      
      // show warning based on notification level setting
      const notificationThresholds = {
        'low': 80, // only show for very high risk
        'medium': 60, // show for medium and high risk
        'high': 40 // show for low, medium, and high risk
      }
      
      const threshold = notificationThresholds[settings.notificationLevel] || 60
      
      // if score exceeds the threshold, notify the user
      if (analysis.score >= threshold) {
        chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          data: {
            score: analysis.score,
            url: tab.url,
            details: analysis.details,
            is_phishing: analysis.is_phishing
          }
        }).catch(err => console.log('Error sending warning to content script:', err))
      }
    } catch (error) {
      console.error('Error in URL analysis:', error)
    }
  }
})

// listen for messages from popup or content script
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