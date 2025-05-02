(() => {
  console.log('Phisher content script loaded');
  
  // Create and inject warning overlay
  function createWarningOverlay(data) {
    // Remove any existing overlay
    removeWarningOverlay();
    
    // Create overlay container
    const overlay = document.createElement('div');
    overlay.id = 'phisher-warning-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.8);
      z-index: 2147483647;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
    `;
    
    // Create warning box
    const warningBox = document.createElement('div');
    warningBox.style.cssText = `
      background-color: white;
      border-radius: 8px;
      padding: 24px;
      max-width: 500px;
      width: 80%;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    `;
    
    // Warning icon and title
    const titleContainer = document.createElement('div');
    titleContainer.style.cssText = `
      display: flex;
      align-items: center;
      margin-bottom: 16px;
    `;
    
    const warningIcon = document.createElement('div');
    warningIcon.innerHTML = `
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 6.49L19.53 19.5H4.47L12 6.49ZM12 2.5L1 21.5H23L12 2.5Z" fill="#D32F2F"/>
        <path d="M13 16.5H11V18.5H13V16.5Z" fill="#D32F2F"/>
        <path d="M13 10.5H11V15.5H13V10.5Z" fill="#D32F2F"/>
      </svg>
    `;
    
    const title = document.createElement('h2');
    title.textContent = 'Phishing Alert';
    title.style.cssText = `
      margin: 0 0 0 16px;
      color: #D32F2F;
      font-size: 24px;
    `;
    
    titleContainer.appendChild(warningIcon);
    titleContainer.appendChild(title);
    
    // Warning message
    const message = document.createElement('p');
    message.textContent = `This website has been flagged as a potential phishing threat with a risk score of ${data.score}/100.`;
    message.style.cssText = `
      margin: 0 0 16px 0;
      font-size: 16px;
      line-height: 1.5;
    `;
    
    // URL display
    const urlContainer = document.createElement('div');
    urlContainer.style.cssText = `
      background-color: #f5f5f5;
      padding: 12px;
      border-radius: 4px;
      margin-bottom: 16px;
      word-break: break-all;
    `;
    
    const urlLabel = document.createElement('div');
    urlLabel.textContent = 'Suspicious URL:';
    urlLabel.style.cssText = `
      font-weight: bold;
      margin-bottom: 8px;
    `;
    
    const urlText = document.createElement('div');
    urlText.textContent = data.url;
    
    urlContainer.appendChild(urlLabel);
    urlContainer.appendChild(urlText);
    
    // Details (if available)
    let detailsContainer = null;
    if (data.details) {
      detailsContainer = document.createElement('div');
      detailsContainer.style.cssText = `
        margin-bottom: 16px;
      `;
      
      const detailsLabel = document.createElement('div');
      detailsLabel.textContent = 'Analysis Details:';
      detailsLabel.style.cssText = `
        font-weight: bold;
        margin-bottom: 8px;
      `;
      
      const detailsText = document.createElement('div');
      detailsText.textContent = data.details;
      
      detailsContainer.appendChild(detailsLabel);
      detailsContainer.appendChild(detailsText);
    }
    
    // Buttons
    const buttonContainer = document.createElement('div');
    buttonContainer.style.cssText = `
      display: flex;
      justify-content: space-between;
    `;
    
    const continueButton = document.createElement('button');
    continueButton.textContent = 'Continue Anyway';
    continueButton.style.cssText = `
      padding: 10px 16px;
      border: none;
      border-radius: 4px;
      background-color: #f5f5f5;
      cursor: pointer;
      font-weight: 500;
      flex: 1;
      margin-right: 8px;
    `;
    
    const goBackButton = document.createElement('button');
    goBackButton.textContent = 'Go Back (Recommended)';
    goBackButton.style.cssText = `
      padding: 10px 16px;
      border: none;
      border-radius: 4px;
      background-color: #0288D1;
      color: white;
      cursor: pointer;
      font-weight: 500;
      flex: 1;
      margin-left: 8px;
    `;
    
    // Add learn more button
    const learnMoreButton = document.createElement('button');
    learnMoreButton.textContent = 'Learn More';
    learnMoreButton.style.cssText = `
      padding: 10px 16px;
      border: none;
      border-radius: 4px;
      background-color: #f5f5f5;
      cursor: pointer;
      font-weight: 500;
      flex: 1;
      margin-left: 8px;
    `;
    
    buttonContainer.appendChild(continueButton);
    buttonContainer.appendChild(learnMoreButton);
    buttonContainer.appendChild(goBackButton);
    
    // Assemble the warning box
    warningBox.appendChild(titleContainer);
    warningBox.appendChild(message);
    warningBox.appendChild(urlContainer);
    if (detailsContainer) {
      warningBox.appendChild(detailsContainer);
    }
    warningBox.appendChild(buttonContainer);
    
    // Assemble the overlay
    overlay.appendChild(warningBox);
    
    // Add to the DOM
    document.body.appendChild(overlay);
    
    // Add event listeners
    continueButton.addEventListener('click', removeWarningOverlay);
    
    goBackButton.addEventListener('click', () => {
      history.back();
    });
    
    learnMoreButton.addEventListener('click', () => {
      window.open('https://phisher-chatbot.com/learn', '_blank');
    });
    
    // Prevent scrolling on the page while the overlay is shown
    document.body.style.overflow = 'hidden';
  }
  
  // Remove warning overlay
  function removeWarningOverlay() {
    const overlay = document.getElementById('phisher-warning-overlay');
    if (overlay) {
      overlay.remove();
      document.body.style.overflow = '';
    }
  }
  
  // Create and inject an analysis result notification
  function createResultNotification(data) {
    // Create notification container
    const notification = document.createElement('div');
    notification.id = 'phisher-notification';
    
    // Determine status colors
    let color, icon, text;
    if (data.score >= 30) {
      color = '#D32F2F'; // Red
      icon = '⚠️';
      text = 'Dangerous';
    } else if (data.score >= 20) {
      color = '#FFA000'; // Orange
      icon = '⚠️';
      text = 'Suspicious';
    } else {
      color = '#00C853'; // Green
      icon = '✓';
      text = 'Safe';
    }
    
    notification.style.cssText = `
      position: fixed;
      top: 16px;
      right: 16px;
      background-color: white;
      border-left: 4px solid ${color};
      border-radius: 4px;
      padding: 12px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      z-index: 2147483646;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      max-width: 300px;
      animation: slideIn 0.3s forwards;
    `;
    
    // Create notification content
    notification.innerHTML = `
      <div style="display: flex; align-items: center;">
        <div style="font-size: 20px; margin-right: 12px;">${icon}</div>
        <div>
          <div style="font-weight: bold; margin-bottom: 4px;">Phisher: ${text}</div>
          <div style="font-size: 14px; color: #757575;">Risk score: ${data.score}/100</div>
        </div>
        <div style="margin-left: auto; cursor: pointer; font-size: 16px;" id="phisher-notification-close">×</div>
      </div>
    `;
    
    // Add styles
    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      
      @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
      }
      
      .slide-out {
        animation: slideOut 0.3s forwards !important;
      }
    `;
    
    document.head.appendChild(style);
    document.body.appendChild(notification);
    
    // Add event listener to close button
    document.getElementById('phisher-notification-close').addEventListener('click', () => {
      notification.classList.add('slide-out');
      setTimeout(() => {
        notification.remove();
      }, 300);
    });
    
    // Auto close after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.classList.add('slide-out');
        setTimeout(() => {
          if (notification.parentNode) {
            notification.remove();
          }
        }, 300);
      }
    }, 5000);
  }
  
  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'showWarning') {
      if (request.data.notificationLevel === 'high') {
        createWarningOverlay(request.data);
      } else {
        // For medium and low levels, we can show a notification instead of an overlay
        createResultNotification(request.data);
      }
    }
    
    if (request.action === 'analysisResult') {
      // Only show a notification if the score is notable
      if (request.data.score >= 30) {
        createResultNotification(request.data);
      }
    }
  });
})();