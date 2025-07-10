// initialize extension
chrome.runtime.onInstalled.addListener(() => {
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
    const urlObj = new URL(url)
    const domain = urlObj.hostname
    const path = urlObj.pathname
    const query = urlObj.search
    
    // Extract domain components using basic parsing (since tldextract isn't available in browser)
    const domainParts = domain.split('.')
    const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : ''
    const domainName = domainParts.length > 2 ? domainParts[domainParts.length - 2] : domainParts[0] || ''
    const subdomain = domainParts.length > 2 ? domainParts.slice(0, -2).join('.') : ''
    
    const features = {}
    
    // === ULTRA-SENSITIVE PHISHING DETECTION (33 FEATURES) ===
    
    // 1. CRITICAL SECURITY INDICATORS
    features.has_ip = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(domain) ? 1 : 0
    features.has_https = url.startsWith('https') ? 1 : 0
    
    // 2. SUSPICIOUS TLD (EXPANDED LIST)
    const ultraSuspiciousTlds = [
      'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'download',
      'link', 'info', 'biz', 'xyz', 'club', 'online', 'site',
      'website', 'space', 'tech', 'store', 'shop', 'win', 'vip',
      'icu', 'rest', 'cc', 'sbs', 'world', 'support'
    ]
    features.suspicious_tld = ultraSuspiciousTlds.includes(tld) ? 1 : 0
    
    // 3. DOMAIN ANALYSIS
    features.domain_length = domainName.length
    features.subdomain_count = subdomain ? subdomain.split('.').length : 0
    features.excessive_subdomains = features.subdomain_count > 2 ? 1 : 0
    features.ultra_excessive_subdomains = features.subdomain_count > 4 ? 1 : 0
    features.has_hyphen_in_domain = domainName.includes('-') ? 1 : 0
    features.multiple_hyphens = (domainName.match(/-/g) || []).length > 1 ? 1 : 0
    
    const digitRatio = (domainName.match(/\d/g) || []).length / Math.max(domainName.length, 1)
    features.high_digit_ratio = digitRatio > 0.2 ? 1 : 0
    
    // 4. URL STRUCTURE ANALYSIS
    features.url_length = url.length
    features.path_length = path.length
    features.query_length = query.length
    features.extremely_long_url = url.length > 100 ? 1 : 0
    features.suspicious_url_length = url.length > 75 ? 1 : 0
    features.deep_path = (path.match(/\//g) || []).length > 3 ? 1 : 0
    features.long_query = query.length > 30 ? 1 : 0
    
    // 5. PHISHING KEYWORDS (ULTRA-COMPREHENSIVE)
    const ultraPhishingKeywords = [
      'verify', 'secure', 'login', 'signin', 'account', 'update', 'confirm',
      'suspended', 'locked', 'expired', 'urgent', 'immediate', 'security',
      'alert', 'warning', 'action', 'required', 'validation', 'authenticate',
      'verification', 'restore', 'unlock', 'resolve', 'customer',
      'banking', 'payment', 'billing', 'invoice', 'transaction', 'refund',
      'card', 'credit', 'debit', 'wallet', 'paypal', 'stripe',
      'support', 'service', 'center', 'portal', 'help', 'notification'
    ]
    
    const keywordCount = ultraPhishingKeywords.filter(kw => url.toLowerCase().includes(kw)).length
    features.keyword_count = keywordCount
    features.has_phishing_keywords = keywordCount >= 1 ? 1 : 0
    features.multiple_phishing_keywords = keywordCount >= 2 ? 1 : 0
    
    // 6. BRAND IMPERSONATION (ULTRA-COMPREHENSIVE)
    const majorBrands = [
      'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta',
      'instagram', 'twitter', 'linkedin', 'youtube', 'netflix', 'spotify',
      'adobe', 'zoom', 'dropbox', 'gmail', 'outlook', 'icloud',
      'paypal', 'stripe', 'visa', 'mastercard', 'amex', 'discover',
      'chase', 'wells', 'bofa', 'citi', 'usbank', 'hsbc', 'td',
      'bankofamerica', 'wellsfargo', 'citibank', 'pnc', 'capitalone',
      'bank', 'credit', 'union', 'financial', 'banking'
    ]
    
    const brandCount = majorBrands.filter(brand => domainName.includes(brand)).length
    features.has_brand_impersonation = brandCount > 0 ? 1 : 0
    
    // 7. SUSPICIOUS DOMAIN PATTERNS
    const suspiciousDomainPatterns = [
      'verification', 'security', 'account', 'update', 'confirm',
      'locked', 'suspended', 'expired', 'urgent', 'immediate',
      'customer', 'support', 'service', 'center', 'portal'
    ]
    const domainPatternCount = suspiciousDomainPatterns.filter(pattern => domainName.includes(pattern)).length
    features.has_suspicious_domain_pattern = domainPatternCount > 0 ? 1 : 0
    
    // 8. URL SHORTENER DETECTION (EXPANDED)
    const shorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
      'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy',
      'cutt.ly', 'bitly.com', 'short.io', 'rebrand.ly'
    ]
    features.is_shortener = shorteners.some(s => domain.includes(s)) ? 1 : 0
    
    // 9. SUSPICIOUS CHARACTERS & PATTERNS
    features.has_at_symbol = url.includes('@') ? 1 : 0
    features.has_double_slash = url.slice(8).includes('//') ? 1 : 0
    
    const specialCharCount = (url.match(/[%\-_=&\?]/g) || []).length
    features.special_char_density = specialCharCount / url.length
    features.high_special_char_density = features.special_char_density > 0.1 ? 1 : 0
    
    // 10. ADVANCED DETECTION
    features.homograph_risk = /[^\x00-\x7F]/.test(domainName) ? 1 : 0
    
    const typosquattingIndicators = [
      domainName.includes('0') && domainName.includes('o'),
      domainName.includes('1') && domainName.includes('l'),
      domainName.includes('5') && domainName.includes('s')
    ]
    features.potential_typosquatting = typosquattingIndicators.some(Boolean) ? 1 : 0
    
    // 11. ENTROPY ANALYSIS
    function calculateEntropy(text) {
      if (!text) return 0
      const charCounts = {}
      for (const char of text.toLowerCase()) {
        charCounts[char] = (charCounts[char] || 0) + 1
      }
      
      let entropy = 0
      const length = text.length
      Object.values(charCounts).forEach(count => {
        if (count > 0) {
          const p = count / length
          entropy -= p * Math.log2(p)
        }
      })
      return entropy
    }
    
    const domainEntropy = calculateEntropy(domainName)
    features.high_domain_entropy = domainEntropy > 3.0 ? 1 : 0
    
    // 12. COMBINED ULTRA-HIGH RISK INDICATORS
    const criticalRiskFactors = [
      features.has_ip,
      features.suspicious_tld,
      features.has_brand_impersonation,
      features.is_shortener,
      features.multiple_phishing_keywords,
      features.excessive_subdomains,
      features.has_suspicious_domain_pattern
    ]
    
    features.risk_factor_count = criticalRiskFactors.reduce((sum, factor) => sum + factor, 0)
    features.multiple_critical_risks = features.risk_factor_count >= 2 ? 1 : 0
    features.ultra_high_risk = features.risk_factor_count >= 3 ? 1 : 0
    
    return features
    
  } catch (error) {
    console.error('Error extracting enhanced features:', error)
    // Return safe defaults for all 33 features
    return {
      has_ip: 0, has_https: 0, suspicious_tld: 0, domain_length: 0,
      subdomain_count: 0, excessive_subdomains: 0, ultra_excessive_subdomains: 0,
      has_hyphen_in_domain: 0, multiple_hyphens: 0, high_digit_ratio: 0, high_domain_entropy: 0,
      url_length: 0, extremely_long_url: 0, suspicious_url_length: 0, deep_path: 0, long_query: 0,
      path_length: 0, query_length: 0, keyword_count: 0, has_phishing_keywords: 0,
      multiple_phishing_keywords: 0, has_brand_impersonation: 0, has_suspicious_domain_pattern: 0,
      is_shortener: 0, has_at_symbol: 0, has_double_slash: 0, special_char_density: 0,
      high_special_char_density: 0, homograph_risk: 0, potential_typosquatting: 0,
      risk_factor_count: 0, multiple_critical_risks: 0, ultra_high_risk: 0
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
  let score = 0
  
  // ULTRA-HIGH PRIORITY INDICATORS (Zero tolerance)
  if (features.has_ip) score += 30
  if (features.is_shortener) score += 25
  if (features.ultra_high_risk) score += 25
  if (features.multiple_critical_risks) score += 20
  
  // HIGH PRIORITY INDICATORS
  if (features.multiple_phishing_keywords) score += 15
  if (features.has_brand_impersonation) score += 15
  if (features.excessive_subdomains) score += 12
  if (features.suspicious_tld) score += 12
  if (features.has_suspicious_domain_pattern) score += 10
  
  // MEDIUM PRIORITY INDICATORS
  if (features.has_phishing_keywords) score += 8
  if (features.high_domain_entropy) score += 8
  if (features.extremely_long_url) score += 7
  if (features.multiple_hyphens) score += 6
  if (!features.has_https) score += 6
  
  // LOW PRIORITY INDICATORS
  if (features.deep_path) score += 4
  if (features.long_query) score += 4
  if (features.high_special_char_density) score += 3
  if (features.potential_typosquatting) score += 3
  if (features.has_at_symbol) score += 5
  if (features.has_double_slash) score += 5
  
  // Ensure we don't exceed 100
  return Math.min(score, 100)
}

// function to make prediction using the ML model via API
async function analyzeSuspiciousUrl(url) {
  try {
    // Extract enhanced features
    const features = extractUrlFeatures(url)
    
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