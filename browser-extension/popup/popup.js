// Update the probability display
function updateProbability(probability) {
  const fill = document.getElementById('probabilityFill');
  const text = document.getElementById('probabilityText');
  
  fill.style.width = `${probability}%`;
  
  // Update color based on probability
  if (probability < 30) {
    fill.className = 'probability-fill safe';
  } else if (probability < 70) {
    fill.className = 'probability-fill warning';
  } else {
    fill.className = 'probability-fill danger';
  }
  
  text.textContent = `Probability: ${probability}%`;
}

// Get current tab's probability when popup opens
chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
  chrome.tabs.sendMessage(tabs[0].id, {action: "getProbability"}, function(response) {
    if (response && response.probability !== undefined) {
      updateProbability(response.probability);
    }
  });
});
