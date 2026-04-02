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

    // YOUR EXACT OLD AI MATH
    if (phishingScore > 0.9) {
      penalty += 55; 
      reasons.push(`CRITICAL AI: Extreme phishing probability (${(phishingScore * 100).toFixed(1)}%)`);
    } else if (phishingScore > 0.7) {
      penalty += 30; 
      reasons.push(`AI Warning: High phishing probability (${(phishingScore * 100).toFixed(1)}%)`);
    } else if (phishingScore > 0.5) {
      penalty += 15; 
      reasons.push(`AI Notice: Suspicious URL semantics (${(phishingScore * 100).toFixed(1)}%)`);
    } else {
      reasons.push(`Random Forest AI: URL semantics appear safe (${((1 - phishingScore) * 100).toFixed(1)}% confidence)`);
    }

  } catch (e) {
    console.error("Random Forest AI Analysis Error:", e);
    
    // 🔥 THE FIX: "Fail Secure" Architecture
    // If the AI is asleep or unreachable, we MUST treat the site as suspicious.
    penalty += 25; 
    
    reasons.push(`AI unavailable (Server waking up / Network issue) — Risk treated as suspicious`);
  }

  return { penalty, reasons };
}

window.NoPhishCloudAI = { analyzeWithCloudAI };