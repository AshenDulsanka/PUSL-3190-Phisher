// initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phisher extension installed')
  
  // set default settings
  chrome.storage.local.set({
    enableRealTimeScanning: true,
    notificationLevel: 'low', // low, high
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
    
    // Basic features
    features.url_length = fullUrl.length
    features.num_dots = fullUrl.split('.').length - 1
    features.has_https = urlObj.protocol === 'https:' ? 1 : 0
    features.has_at_symbol = fullUrl.includes('@') ? 1 : 0
    
    // IP detection
    features.has_ip = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(domain) ? 1 : 0
    
    // Domain analysis
    features.domain_length = domain.length
    features.has_hyphen = domain.includes('-') ? 1 : 0
    
    // Subdomain count (approximate)
    features.subdomain_count = Math.max(0, domain.split('.').length - 2)
    
    // Suspicious TLD
    const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq']
    const tld = domain.split('.').pop()
    features.suspicious_tld = suspiciousTlds.includes(tld) ? 1 : 0
    
    // URL shortener
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co']
    features.url_shortener = shorteners.some(s => domain.includes(s)) ? 1 : 0
    
    // Special character ratio
    const specialChars = fullUrl.replace(/[a-zA-Z0-9.]/g, '').length
    features.special_char_ratio = specialChars / fullUrl.length
    
    // Suspicious keywords
    const suspiciousKeywords = ['verify', 'secure', 'account', 'login']
    features.suspicious_keywords = suspiciousKeywords.filter(kw => fullUrl.toLowerCase().includes(kw)).length
    
    // Brand keywords
    const brandKeywords = ['paypal', 'amazon', 'google']
    features.brand_keywords = brandKeywords.filter(brand => domain.toLowerCase().includes(brand)).length
    
    return features
  } catch (error) {
    console.error('Error extracting features:', error)
    return {
      url_length: 0, num_dots: 0, has_https: 0, has_at_symbol: 0,
      has_ip: 0, domain_length: 0, has_hyphen: 0, subdomain_count: 0,
      suspicious_tld: 0, url_shortener: 0, special_char_ratio: 0,
      suspicious_keywords: 0, brand_keywords: 0
    }
  }
}

// helper function to calculate entropy (randomness) of URL
function calculateEntropy(text) {
  if (!text) return 0
  
  // count character frequencies
  const charFreq = {}
  for (let i = 0; i < text.length; i++) {
    const char = text[i].toLowerCase()
    charFreq[char] = (charFreq[char] || 0) + 1
  }
  
  // calculate entropy
  let entropy = 0
  const len = text.length
  Object.values(charFreq).forEach(count => {
    const p = count / len
    entropy -= p * Math.log2(p)
  })
  
  return entropy
}

// heuristic scoring as fallback when API is unavailable
function calculateHeuristicScore(features, url) {
  let score = 0;
  
  // High-risk indicators
  if (features.has_ip) score += 25;
  if (features.url_shortener) score += 20;
  if (features.suspicious_keywords >= 2) score += 15;
  if (features.brand_keywords >= 2) score += 20;
  
  // Medium-risk indicators
  if (features.domain_entropy > 4) score += 10;
  if (features.suspicious_tld) score += 15;
  if (features.homograph_attack > 0) score += 10;
  if (!features.has_https) score += 10;
  
  // Low-risk indicators
  if (features.url_length > 100) score += 5;
  if (features.subdomain_count > 3) score += 5;
  if (features.special_char_ratio > 0.3) score += 5;
  
  // Additional context checks
  const suspiciousPatterns = [
    /secure.*verify/i,
    /account.*suspended/i,
    /urgent.*action/i,
    /confirm.*identity/i,
    /update.*payment/i
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(url)) {
      score += 10;
      break;
    }
  }
  
  return Math.min(score, 100);
}

// function to make prediction using the ML model via API
async function analyzeSuspiciousUrl(url) {
  try {
    // Extract enhanced features
    const features = extractEnhancedUrlFeatures(url)
    
    // Try ML API first
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, client: 'browser_extension' })
    })
    
    if (response.ok) {
      const data = await response.json();
      return {
        score: data.threat_score || 0,
        is_phishing: data.is_phishing || false,
        status: data.is_phishing ? 'Warning' : 'Safe',
        details: data.details || 'URL analyzed successfully',
        confidence: data.confidence || 'Medium'
      }
    }
    
    // Fallback to enhanced heuristics
    const heuristicScore = calculateHeuristicScore(features, url)
    
    return {
      score: heuristicScore,
      is_phishing: heuristicScore >= 40,
      status: heuristicScore >= 40 ? 'Warning' : heuristicScore >= 25 ? 'Suspicious' : 'Safe',
      details: 'Analyzed using offline detection (API unavailable)',
      confidence: 'Medium'
    }
    
  } catch (error) {
    console.error('Error analyzing URL:', error);
    return {
      score: 0,
      is_phishing: false,
      status: 'Unknown',
      details: 'Analysis failed',
      confidence: 'Low'
    }
  }
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
      if (analysis.score >= 30) {
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' })
        chrome.action.setBadgeText({ text: '!' })
      } else if (analysis.score >= 20) {
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
        'low': 30, // only show for very high risk
        'high': 20 // show for low, and high risk
      }
      
      const threshold = notificationThresholds[settings.notificationLevel] || 20
      
      // if score exceeds the threshold, notify the user
      if (analysis.score >= threshold) {
        chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          data: {
            score: analysis.score,
            url: tab.url,
            details: analysis.details,
            is_phishing: analysis.is_phishing >= 30,
            notificationLevel: settings.notificationLevel
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

// listen for tab activation to update the badge
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    // get the active tab
    const tab = await chrome.tabs.get(activeInfo.tabId)
    
    // skip if not an HTTP URL
    if (!tab.url || !tab.url.startsWith('http')) {
      chrome.action.setBadgeText({ text: '' })  // clear badge for non-HTTP pages
      return
    }
    
    // get last analysis for this URL
    const data = await chrome.storage.local.get('lastAnalysis')
    if (data.lastAnalysis && data.lastAnalysis.url === tab.url) {
      // cached analysis for this URL
      const analysis = data.lastAnalysis.result
      
      // update badge based on risk level
      if (analysis.score >= 30) {
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' })
        chrome.action.setBadgeText({ text: '!' })
      } else if (analysis.score >= 20) {
        chrome.action.setBadgeBackgroundColor({ color: '#FFA500' })
        chrome.action.setBadgeText({ text: '?' })
      } else {
        chrome.action.setBadgeBackgroundColor({ color: '#00C853' })
        chrome.action.setBadgeText({ text: '✓' })
      }
    } else {
      // no cached analysis, clear badge until analysis completes
      chrome.action.setBadgeText({ text: '' })
    }
  } catch (error) {
    console.error('Error updating badge on tab activation:', error)
  }
})