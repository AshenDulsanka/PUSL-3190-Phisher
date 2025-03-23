// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phisher extension installed');
    
    // Set default settings
    chrome.storage.local.set({
      enableRealTimeScanning: true,
      notificationLevel: 'medium', // low, medium, high
      redirectThreshold: 30
    });
  });
  
  // API endpoint for ML model
  const API_ENDPOINT = process.env.BROWSER_EXTENSION_API_ENDPOINT;
  
  // Function to extract features from URL
  function extractUrlFeatures(url) {
    // Basic feature extraction - this would be enhanced in a production system
    const urlObj = new URL(url);
    
    const features = {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      pathname: urlObj.pathname,
      hasSubdomain: urlObj.hostname.split('.').length > 2,
      domainLength: urlObj.hostname.length,
      numSpecialChars: (url.match(/[^a-zA-Z0-9]/g) || []).length,
      hasIP: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)
    };
    
    return features;
  }
  
  // Function to make prediction using the ML model via API
  async function analyzeSuspiciousUrl(url) {
    try {
      // For development/testing - simulate an API response
      if (process.env.NODE_ENV === 'development') {
        // Simulate different scores for demo purposes
        const score = url.includes('login') || url.includes('signin') ? 
          Math.floor(Math.random() * 70) + 30 : 
          Math.floor(Math.random() * 30);
        
        return {
          score: score,
          status: score > 60 ? 'Warning' : score > 20 ? 'Safe' : 'None',
          details: 'Simulated analysis for development'
        };
      }
      
      // Extract features
      const features = extractUrlFeatures(url);
      
      // Call the API for real analysis
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url, features })
      });
      
      if (!response.ok) {
        throw new Error('API request failed');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error analyzing URL:', error);
      return {
        score: 0,
        status: 'Error',
        details: 'Could not analyze URL'
      };
    }
  }
  
  // Listen for tab updates to check URLs
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Check if the tab has completed loading and has a URL
    if (changeInfo.status === 'complete' && tab.url) {
      // Skip browser internal pages
      if (!tab.url.startsWith('http')) return;
      
      // Get settings
      const settings = await chrome.storage.local.get([
        'enableRealTimeScanning',
        'redirectThreshold'
      ]);
      
      // Skip if real-time scanning is disabled
      if (!settings.enableRealTimeScanning) return;
      
      const analysis = await analyzeSuspiciousUrl(tab.url);
      
      // Send analysis result to content script
      chrome.tabs.sendMessage(tabId, {
        action: 'analysisResult',
        data: analysis
      });
      
      // Update badge based on risk level
      if (analysis.score > 60) {
        chrome.action.setBadgeBackgroundColor({ color: '#FF5F5F' });
        chrome.action.setBadgeText({ text: '!' });
      } else if (analysis.score > 20) {
        chrome.action.setBadgeBackgroundColor({ color: '#75D7BE' });
        chrome.action.setBadgeText({ text: '✓' });
      } else {
        chrome.action.setBadgeText({ text: '' });
      }
      
      // Store the result for the popup to access
      chrome.storage.local.set({ lastAnalysis: {
        url: tab.url,
        result: analysis,
        timestamp: Date.now()
      }});
      
      // If score exceeds the redirect threshold, notify the user
      if (analysis.score >= settings.redirectThreshold) {
        chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          data: {
            score: analysis.score,
            url: tab.url
          }
        });
      }
    }
  });
  
  // Listen for messages from popup or content script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeUrl') {
      analyzeSuspiciousUrl(request.url)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ error: error.message }));
      return true; 
    }
    
    if (request.action === 'getLastAnalysis') {
      chrome.storage.local.get('lastAnalysis', (data) => {
        sendResponse(data.lastAnalysis || null);
      });
      return true; 
    }
  });