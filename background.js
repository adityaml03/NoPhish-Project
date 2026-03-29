// Background Service Worker
// This runs in the background and has permission to talk to the Cloud API

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeWithCloudAI") {
    
    console.log("Background script received request to analyze:", request.url);

    // The background script talks to the Render Cloud server
    fetch("https://nophish-backend.onrender.com/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ websiteUrl: request.url })
    })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return response.json();
    })
    .then(data => {
      console.log("Background script got data from server:", data);
      sendResponse({ success: true, data: data });
    })
    .catch(error => {
      console.error("Background script fetch error:", error);
      sendResponse({ success: false, error: error.message });
    });

    // Return true to indicate we will send a response asynchronously
    return true; 
  }
});