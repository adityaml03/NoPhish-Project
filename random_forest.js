// Pre-navigation Random Forest AI Analysis
async function analyzeWithCloudAI(urlStr) {
  let penalty = 0;
  let reasons = [];
  
  try {
    console.log("NoPhish: Asking background script to query Random Forest AI server...");
    
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { action: "analyzeWithCloudAI", url: urlStr },
        (res) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(res);
          }
        }
      );
    });

    if (!response || !response.success) {
      throw new Error(response ? response.error : "No response from background script");
    }

    const result = response.data;
    let phishingScore = 0;
    let predictions = [];
    
    if (Array.isArray(result)) {
      predictions = Array.isArray(result[0]) ? result[0] : result; 
    } else if (result && typeof result === 'object') {
      if (result.label && result.score !== undefined) {
        predictions = [result];
      } else if (result.phishingScore !== undefined) {
        phishingScore = result.phishingScore;
      } else if (result.score !== undefined) {
        phishingScore = result.score;
      } else if (result.error) {
        throw new Error(result.error);
      }
    } else if (typeof result === 'number') {
      phishingScore = result;
    }
    
    if (predictions.length > 0) {
      for (const pred of predictions) {
        if (!pred || !pred.label) continue;
        const label = String(pred.label).toLowerCase();
        if (label.includes("phishing") || label.includes("malicious") || label === "label_1" || label === "bad") {
          phishingScore = pred.score;
        }
      }
    }

    phishingScore = Number(phishingScore);
    if (isNaN(phishingScore)) phishingScore = 0;
    if (phishingScore > 1) phishingScore = phishingScore / 100; 

    if (phishingScore > 0.8) {
      penalty += 60;
      reasons.push(`Random Forest AI: High phishing probability (${(phishingScore * 100).toFixed(1)}%)`);
    } else if (phishingScore > 0.5) {
      penalty += 30;
      reasons.push(`Random Forest AI: Suspicious URL semantics (${(phishingScore * 100).toFixed(1)}%)`);
    } else {
      reasons.push(`Random Forest AI: URL semantics appear safe (${((1 - phishingScore) * 100).toFixed(1)}% confidence)`);
    }

  } catch (e) {
    console.error("Random Forest AI Analysis Error:", e);
    // If it fails, it means Render is waking up!
    reasons.push(`Random Forest AI: Server is waking up (Takes ~50s). Please refresh the page!`);
  }

  return { penalty, reasons };
}

// We keep this variable name the same so we don't have to rewrite content.js!
window.NoPhishCloudAI = { analyzeWithCloudAI };