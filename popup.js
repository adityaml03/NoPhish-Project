document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const currentTab = tabs[0];
    
    // Cannot inject into chrome:// or edge:// URLs
    if (currentTab.url.startsWith('chrome://') || currentTab.url.startsWith('edge://') || currentTab.url.startsWith('about:')) {
      document.getElementById('loading').textContent = 'NoPhish cannot scan internal browser pages.';
      return;
    }

    chrome.tabs.sendMessage(currentTab.id, {action: "getAnalysis"}, (response) => {
      if (chrome.runtime.lastError || !response) {
        document.getElementById('loading').textContent = 'Please refresh the page to enable NoPhish scanning.';
        return;
      }

      if (response.status === 'analyzing') {
        document.getElementById('loading').textContent = 'Still analyzing page... Please wait a moment and reopen.';
        return;
      }

      document.getElementById('loading').style.display = 'none';
      document.getElementById('result').style.display = 'block';
      
      const circle = document.getElementById('scoreCircle');
      document.getElementById('scoreValue').textContent = response.score;
      circle.className = `score-circle ${response.risk}`;
      
      const statusText = document.getElementById('statusText');
      statusText.textContent = response.risk === 'danger' ? 'Highly Malicious' : response.risk === 'warning' ? 'Suspicious' : 'Safe to Browse';
      statusText.style.color = response.risk === 'danger' ? '#ef4444' : response.risk === 'warning' ? '#eab308' : '#22c55e';

      const ul = document.getElementById('reasonsList');
      if (response.reasons && response.reasons.length === 0) {
        ul.innerHTML = '<li>✅ No suspicious indicators found.</li>';
      } else if (response.reasons) {
        response.reasons.forEach(r => {
          const li = document.createElement('li');
          li.textContent = r;
          ul.appendChild(li);
        });
      }
    });
  });
});
