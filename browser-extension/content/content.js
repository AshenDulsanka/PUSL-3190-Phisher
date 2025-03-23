// Warning banner element
let warningBanner = null;

// Function to create and show the warning banner
function showWarningBanner(data) {
  // Remove existing banner if present
  removeWarningBanner();
  
  // Create new banner
  warningBanner = document.createElement('div');
  warningBanner.className = 'phisher-warning-banner';
  
  // Create warning content
  warningBanner.innerHTML = `
    <div class="phisher-warning-content">
      <div class="phisher-warning-icon">⚠️</div>
      <div class="phisher-warning-text">
        <strong>Phishing Alert!</strong>
        <p>This website has been flagged as potentially dangerous (Score: ${data.score}/100).</p>
      </div>
      <div class="phisher-warning-actions">
        <button id="phisher-analyze-btn" class="phisher-btn">Deep Analysis</button>
        <button id="phisher-dismiss-btn" class="phisher-btn phisher-dismiss-btn">Dismiss</button>
      </div>
    </div>
  `;
  
  // Append to body
  document.body.prepend(warningBanner);
  
  // Add event listeners
  document.getElementById('phisher-analyze-btn').addEventListener('click', () => {
    // Open the chatbot in a new tab for deep analysis
    window.open(`https://chatbot-url.com?url=${encodeURIComponent(data.url)}`, '_blank');
  });
  
  document.getElementById('phisher-dismiss-btn').addEventListener('click', () => {
    removeWarningBanner();
  });
}

// Function to remove the warning banner
function removeWarningBanner() {
  if (warningBanner && warningBanner.parentNode) {
    warningBanner.parentNode.removeChild(warningBanner);
    warningBanner = null;
  }
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showWarning') {
    showWarningBanner(request.data);
  }
  
  if (request.action === 'analysisResult') {
    // Update the page if needed based on analysis result
    console.log('Analysis result received in content script:', request.data);
    
    // update page elements based on the analysis result
    if (request.data.score > 80) {
      document.body.style.opacity = '0.5';
      showWarningBanner(request.data);
    }
  }
});

// Initial check when content script loads
chrome.runtime.sendMessage({ action: 'getLastAnalysis' }, (response) => {
  if (response && response.result && response.result.score >= 60) {
    showWarningBanner({
      score: response.result.score,
      url: response.url
    });
  }
});