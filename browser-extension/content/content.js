// List of common phishing indicators
const phishingIndicators = {
  suspiciousURLPatterns: [
    /^[0-9]+\./,                    // IP address as domain
    /paypal.*\.com(?!\.)/,          // Paypal lookalike
    /bank.*\.com(?!\.)/,            // Bank lookalike
    /\.tk$/,                        // Free domains
    /\.xyz$/,
    /\.(cc|gq|ml|cf)$/,
    /.*\.com-[A-Za-z0-9]+\./       // Subdomain tricks
  ],
  suspiciousTerms: [
    'login',
    'signin',
    'verify',
    'account',
    'security',
    'update',
    'confirm'
  ]
};

function calculatePhishingProbability() {
  let probability = 0;
  const currentURL = window.location.href;
  const domain = window.location.hostname;
  
  // Check URL patterns
  phishingIndicators.suspiciousURLPatterns.forEach(pattern => {
    if (pattern.test(domain)) {
      probability += 15;
    }
  });

  // Check for suspicious terms in URL
  phishingIndicators.suspiciousTerms.forEach(term => {
    if (currentURL.toLowerCase().includes(term)) {
      probability += 5;
    }
  });

  // Check for SSL
  if (!currentURL.startsWith('https')) {
    probability += 10;
  }

  // Check for suspicious input fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const loginFields = document.querySelectorAll('input[type="text"], input[type="email"]');
  if (passwordFields.length > 0 && loginFields.length > 0) {
    probability += 10;
  }

  // Cap probability at 100
  return Math.min(probability, 100);
}

// Main function to check the website
function checkWebsite() {
  const probability = calculatePhishingProbability();
  
  // Send probability to background script
  chrome.runtime.sendMessage({
    action: 'updateProbability',
    probability: probability
  });

  // If probability is over 30%, show warning
  if (probability >= 30) {
    showWarning(probability);
  }
}

// Function to show warning popup
function showWarning(probability) {
  const warningDiv = document.createElement('div');
  warningDiv.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 20px;
    background-color: #ff4444;
    color: white;
    border-radius: 8px;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    max-width: 300px;
  `;

  warningDiv.innerHTML = `
    <h3 style="margin: 0 0 10px 0">⚠️ Phishing Risk Detected!</h3>
    <p style="margin: 0 0 10px 0">This website has a ${probability}% chance of being a phishing site.</p>
    <button id="checkWithAI" style="
      background: white;
      color: #ff4444;
      border: none;
      padding: 8px 16px;
      border-radius: 4px;
      cursor: pointer;
      margin-right: 10px;
    ">Check with AI Detector</button>
    <button id="dismissWarning" style="
      background: transparent;
      color: white;
      border: 1px solid white;
      padding: 8px 16px;
      border-radius: 4px;
      cursor: pointer;
    ">Dismiss</button>
  `;

  document.body.appendChild(warningDiv);

  // Add event listeners
  document.getElementById('checkWithAI').addEventListener('click', () => {
    // Replace with your AI detector URL
    window.open('YOUR_AI_DETECTOR_URL?url=' + encodeURIComponent(window.location.href), '_blank');
  });

  document.getElementById('dismissWarning').addEventListener('click', () => {
    warningDiv.remove();
  });
}

// Run check when page loads
window.addEventListener('load', checkWebsite);
